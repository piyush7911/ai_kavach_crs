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
import json
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


def _dynamic(url: str) -> list[Finding]:
    from src.pyauto.probes import (ProbeCtx, enrich_routes, mine_params, probe,
                                   routes_from_crawl, routes_from_sitemap, Route)
    pu = urlparse(url.rstrip("/"))
    origin = f"{pu.scheme}://{pu.netloc}"
    ctx_path = pu.path.rstrip("/")
    merged: dict = {}
    for r in (routes_from_crawl(origin, seeds=((ctx_path + "/") or "/",))
              + routes_from_sitemap(f"{origin}{ctx_path}/sitemap.xml")
              + routes_from_sitemap(f"{origin}/sitemap.xml")):
        merged.setdefault((r.method, r.path), set()).update(r.query_fields)
    routes = [Route(m, p, query_fields=sorted(ps)) for (m, p), ps in sorted(merged.items())]
    ctx = ProbeCtx(origin, auth={}, reseed=None)
    mine_params(origin, routes, ctx)
    enrich_routes(routes, ctx)
    return probe(routes, ctx)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmarks.kavach")
    ap.add_argument("--target", help="source tree (stack auto-detected)")
    ap.add_argument("--url", help="running app base URL for dynamic discovery + confirmation")
    ap.add_argument("--zap", help="an OWASP ZAP JSON report to ingest as candidates")
    ap.add_argument("--out", default="", help="write the merged findings JSON here")
    args = ap.parse_args(argv)
    if not (args.target or args.url or args.zap):
        ap.error("give at least one of --target / --url / --zap")

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
        d = _dynamic(args.url)
        print(f"[dynamic] {len(d)} CONFIRMED")
        findings += d
    if args.zap:
        from benchmarks.scanners.zap import findings_from_zap
        z = findings_from_zap(args.zap)
        print(f"[zap] {len(z)} candidate(s) ingested")
        if args.url:                                   # re-test ZAP's alerts with our own oracle
            from src.pyauto.probes import ProbeCtx, confirm_candidates
            pu = urlparse(args.url.rstrip("/"))
            confirm_candidates(z, ProbeCtx(f"{pu.scheme}://{pu.netloc}", auth={}, reseed=None))
            print(f"[zap] {sum(1 for f in z if f.status == 'confirmed')} confirmed by our oracle, "
                  f"{sum(1 for f in z if f.status != 'confirmed')} left candidate")
        findings += z

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
