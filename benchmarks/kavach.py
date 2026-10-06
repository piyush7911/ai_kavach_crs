"""AI Kavach — one generalized entry point for ANY app.

Point it at a source tree and/or a running URL and it: (1) auto-detects the stack and runs the matching
static detector, (2) if a URL is given, discovers routes over HTTP (crawl + sitemap + parameter mining)
and runs the oracle families to CONFIRM bugs, (3) optionally ingests an external scanner's report (ZAP
today) as extra candidates, then confirms those too. Output is one merged, de-duplicated finding list:
`confirmed` = a replayed exploit succeeded (no false positive), `candidate` = flagged but not yet proven.

    python -m benchmarks.kavach --target ./app                     # static only, stack auto-detected
    python -m benchmarks.kavach --url http://127.0.0.1:9090/App    # dynamic discover + confirm
    python -m benchmarks.kavach --url http://... --zap zap.json    # also ingest + confirm ZAP's alerts
    python -m benchmarks.kavach --target ./app --url http://... --out report.json

Fixing is per-backend and heavier (JS/Py rerun instantly, Java rebuilds), so it stays a separate step
(benchmarks.*fix*); this runner is detect -> discover -> confirm -> report, and it works on any app.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from src.jsauto.findings import Finding


def detect_stack(target: Path) -> str | None:
    """Which backend fits this source tree — by the files a project of that stack must ship."""
    if (target / "package.json").exists():
        return "js"
    if (target / "build.gradle").exists() or (target / "pom.xml").exists() or next(target.rglob("*.java"), None):
        return "java"
    if (target / "requirements.txt").exists() or (target / "pyproject.toml").exists() or next(target.rglob("*.py"), None):
        return "python"
    return None


def _static(stack: str, target: Path) -> list[Finding]:
    if stack == "js":
        from src.jsauto import static
        return static.scan(target)["findings"]
    if stack == "python":
        from src.pyauto import static
        return static.scan(target)
    if stack == "java":
        from src.javaauto import static
        return static.scan(target)
    return []


def _dynamic(url: str, zap_report: str | None = None, nuclei_report: str | None = None) -> list[Finding]:
    from src.pyauto.probes import (ProbeCtx, enrich_routes, mine_params, probe,
                                   routes_from_crawl, routes_from_sitemap, Route)
    pu = urlparse(url.rstrip("/"))
    origin = f"{pu.scheme}://{pu.netloc}"
    ctx_path = pu.path.rstrip("/")
    sources = (routes_from_crawl(origin, seeds=((ctx_path + "/") or "/",))
               + routes_from_sitemap(f"{origin}{ctx_path}/sitemap.xml")
               + routes_from_sitemap(f"{origin}/sitemap.xml"))
    if zap_report:                                     # a scanner's spider reaches routes/params we miss
        from benchmarks.scanners.zap import routes_from_zap
        zr = routes_from_zap(zap_report)
        print(f"[dynamic] +{len(zr)} routes from ZAP's crawl")
        sources += zr
    if nuclei_report:
        from benchmarks.scanners.nuclei import routes_from_nuclei
        nr = routes_from_nuclei(nuclei_report)
        print(f"[dynamic] +{len(nr)} routes from Nuclei")
        sources += nr
    merged: dict = {}
    for r in sources:
        merged.setdefault((r.method, r.path), set()).update(r.query_fields)
    routes = [Route(m, p, query_fields=sorted(ps)) for (m, p), ps in sorted(merged.items())]
    ctx = ProbeCtx(origin, auth={}, reseed=None)
    mine_params(origin, routes, ctx)                   # routes that already have params (from ZAP) are skipped
    enrich_routes(routes, ctx)
    return probe(routes, ctx)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmarks.kavach")
    ap.add_argument("--target", help="source tree (stack auto-detected)")
    ap.add_argument("--url", help="running app base URL for dynamic discovery + confirmation")
    ap.add_argument("--zap", help="an OWASP ZAP JSON report to ingest as candidates")
    ap.add_argument("--trivy", help="a Trivy JSON report (deps/CVEs/IaC/secrets) to ingest as candidates")
    ap.add_argument("--nuclei", help="a Nuclei JSONL report to ingest + confirm")
    ap.add_argument("--out", default="", help="write the merged findings JSON here")
    args = ap.parse_args(argv)
    if not (args.target or args.url or args.zap or args.trivy or args.nuclei):
        ap.error("give at least one of --target / --url / --zap / --trivy / --nuclei")

    findings: list[Finding] = []
    if args.target:
        target = Path(args.target)
        stack = detect_stack(target)
        print(f"[static] stack = {stack or 'unknown'}")
        if stack:
            s = _static(stack, target)
            print(f"[static] {len(s)} candidate(s)")
            findings += s
    if args.url:
        print(f"[dynamic] discovering + confirming on {args.url} ...")
        d = _dynamic(args.url, zap_report=args.zap, nuclei_report=args.nuclei)
        print(f"[dynamic] {len(d)} CONFIRMED")
        findings += d

    # confirmable scanners: ingest their alerts, then re-test each with our oracle (real -> confirmed)
    from benchmarks.scanners.nuclei import findings_from_nuclei
    from benchmarks.scanners.zap import findings_from_zap
    for report, label, loader in ((args.zap, "zap", findings_from_zap), (args.nuclei, "nuclei", findings_from_nuclei)):
        if not report:
            continue
        cand = loader(report)
        print(f"[{label}] {len(cand)} candidate(s) ingested")
        if args.url:
            from src.pyauto.probes import ProbeCtx, confirm_candidates
            pu = urlparse(args.url.rstrip("/"))
            confirm_candidates(cand, ProbeCtx(f"{pu.scheme}://{pu.netloc}", auth={}, reseed=None))
            print(f"[{label}] {sum(1 for f in cand if f.status == 'confirmed')} confirmed by our oracle, "
                  f"{sum(1 for f in cand if f.status != 'confirmed')} left candidate")
        findings += cand
    if args.trivy:
        from benchmarks.scanners.trivy import findings_from_trivy
        t = findings_from_trivy(args.trivy)
        print(f"[trivy] {len(t)} candidate(s) ingested (deps/CVEs/IaC/secrets — source-level, not HTTP-confirmable)")
        findings += t

    confirmed = [f for f in findings if f.status == "confirmed"]
    print(f"\n== {len(findings)} findings: {len(confirmed)} confirmed, {len(findings) - len(confirmed)} candidate ==")
    for f in sorted(findings, key=lambda x: (x.status != "confirmed", x.klass)):
        where = f.evidence.get("route") or (f"{f.file}:{f.line}" if f.line else f.file)
        print(f"  [{f.status:9}] {f.klass:24} {f.source:7} {where}")
    if args.out:
        from src.jsauto.findings import dump
        dump(findings, args.out)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
