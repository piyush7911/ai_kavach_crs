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
    try:
        if stack == "js":
            from src.jsauto import static
            return static.scan(target)["findings"]
        if stack == "python":
            from src.pyauto import static
            return static.scan(target)
        if stack == "java":
            from src.javaauto import static
            return static.scan(target)
    except ImportError as e:                           # a tree-sitter grammar not vendored: skip static, keep going
        print(f"[static] {stack} parser unavailable ({e}); skipping static scan "
              "(scanner/Joern candidates + dynamic confirm still run)")
    return []


def _dynamic(url: str, zap_report: str | None = None, nuclei_report: str | None = None,
             llm: object | None = None, surface: bool = False, attacks: bool = False,
             target: str | None = None) -> tuple:
    from src.pyauto.probes import (ProbeCtx, enrich_routes, mine_params, probe,
                                   routes_from_crawl, routes_from_sitemap, Route)
    pu = urlparse(url.rstrip("/"))
    origin = f"{pu.scheme}://{pu.netloc}"
    ctx_path = pu.path.rstrip("/")
    sources = (routes_from_crawl(origin, seeds=((ctx_path + "/") or "/",))
               + routes_from_sitemap(f"{origin}{ctx_path}/sitemap.xml")
               + routes_from_sitemap(f"{origin}/sitemap.xml"))
    if surface and llm:                                # Slice A: LLM reads the app's HTML/JS -> routes+params
        from src.pyauto.llm_surface import gather_surface_text, propose_routes
        lr = propose_routes(gather_surface_text(origin, ctx_path), llm)
        print(f"[dynamic] +{len(lr)} routes proposed by the LLM from HTML/JS")
        sources += lr
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
    from src.pyauto.probes import coverage
    found = probe(routes, ctx)
    if attacks and llm:                                # Slice B: LLM proposes param+class for GAP routes
        from benchmarks.oracles import Session
        from src.pyauto.llm_attacks import propose_candidates
        from src.pyauto.probes import confirm_candidates

        def fetch(r):
            try:
                return Session(origin).request(r.method, r.path).body
            except Exception:  # noqa: BLE001
                return ""
        source_for = None
        if target:                                     # Slice B.5: read the handler source for exact params
            from src.pyauto.llm_attacks import make_source_lookup
            source_for = make_source_lookup(target)
        cands = propose_candidates(routes, llm, fetch, source_for=source_for)
        confirm_candidates(cands, ctx)                 # our sound oracle decides — not the LLM
        newc = [c for c in cands if c.status == "confirmed"]
        print(f"[llm-attacks] {len(cands)} param/class hypotheses on gap routes → {len(newc)} CONFIRMED by oracle")
        found += newc
    return found, coverage(routes, found), routes


def _build_probe_llm():
    """The exploit/surface model (plan 010): reuses the OpenAI-compatible wiring, its own role MODEL_PROBE
    (falls back to MODEL), local/air-gap endpoint via OPENAI_BASE_URL. Returns a `llm(prompt)->str` or None."""
    import json
    import os
    import urllib.request
    base = os.environ.get("OPENAI_BASE_URL")
    if not base:
        return None
    model = os.environ.get("MODEL_PROBE") or os.environ.get("MODEL", "codegemma:7b")
    key = os.environ.get("OPENAI_API_KEY", "x")

    def llm(prompt: str) -> str:
        # OpenAI-compatible /chat/completions over plain HTTP (works for ollama and any compat endpoint) —
        # no openai SDK dependency, which keeps the air-gapped runner install-free.
        body = json.dumps({"model": model, "temperature": 0, "max_tokens": 1500,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(f"{base.rstrip('/')}/chat/completions", data=body,
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.load(r)
        return data["choices"][0]["message"]["content"] or ""
    return llm


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmarks.kavach")
    ap.add_argument("--target", help="source tree (stack auto-detected)")
    ap.add_argument("--url", help="running app base URL for dynamic discovery + confirmation")
    ap.add_argument("--zap", help="an OWASP ZAP JSON report to ingest as candidates")
    ap.add_argument("--trivy", help="a Trivy JSON report (deps/CVEs/IaC/secrets) to ingest as candidates")
    ap.add_argument("--opengrep", action="store_true",
                    help="run Opengrep over --target as a candidate source (defaults to the vendored "
                         "community corpus for breadth, else our taint rules)")
    ap.add_argument("--opengrep-rules", default="", help="rules file/dir for --opengrep (override the default)")
    ap.add_argument("--joern", help="a Joern taint TSV (cross-file flows) to ingest as candidates")
    ap.add_argument("--nuclei", help="a Nuclei JSONL report to ingest + confirm")
    ap.add_argument("--llm-surface", action="store_true",
                    help="plan 010 Slice A: let the LLM read HTML/JS and propose routes+params (needs "
                         "OPENAI_BASE_URL + MODEL_PROBE/MODEL)")
    ap.add_argument("--llm-attacks", action="store_true",
                    help="plan 010 Slice B: LLM proposes {param,class} for gap routes; our oracle confirms")
    ap.add_argument("--out", default="", help="write the merged findings JSON here")
    args = ap.parse_args(argv)
    if not (args.target or args.url or args.zap or args.trivy or args.nuclei or args.opengrep or args.joern):
        ap.error("give at least one of --target / --url / --zap / --trivy / --nuclei / --opengrep / --joern")

    findings: list[Finding] = []
    if args.target:
        target = Path(args.target)
        stack = detect_stack(target)
        print(f"[static] stack = {stack or 'unknown'}")
        if stack:
            s = _static(stack, target)
            print(f"[static] {len(s)} candidate(s)")
            findings += s
    want_llm = args.llm_surface or args.llm_attacks
    llm = _build_probe_llm() if want_llm else None
    if want_llm and llm is None:
        print("[llm] --llm-* set but no OPENAI_BASE_URL — skipping LLM fallback")
    cov, routes = None, []
    if args.url:
        print(f"[dynamic] discovering + confirming on {args.url} ...")
        d, cov, routes = _dynamic(args.url, zap_report=args.zap, nuclei_report=args.nuclei,
                                  llm=llm, surface=args.llm_surface, attacks=args.llm_attacks, target=args.target)
        print(f"[dynamic] {len(d)} CONFIRMED")
        print(f"[coverage] examined {cov['routes_examined']} routes; actively ATTACKED "
              f"{cov['routes_attacked']} ({cov['attack_coverage_pct']}%); attack-gap {cov['attack_gap']} "
              f"(surface with no parameter we could inject)")
        if cov["attack_gap"]:
            print("[coverage] attack-gap > 0 → NOT 'clean'; this is where the LLM fallback (plan 010) will engage")
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
    if args.opengrep:
        if not args.target:
            print("[opengrep] needs --target (a source tree) — skipping")
        else:
            from pathlib import Path as _P
            from benchmarks.scanners.opengrep import findings_from_opengrep
            og = findings_from_opengrep(args.target, rules=_P(args.opengrep_rules) if args.opengrep_rules else None)
            print(f"[opengrep] {len(og)} candidate(s) (confirming over HTTP needs source→route correlation — "
                  f"reported as candidates)")
            findings += og

    if args.joern:
        from benchmarks.scanners.joern import findings_from_joern
        jf = findings_from_joern(args.joern)
        print(f"[joern] {len(jf)} cross-file taint candidate(s) (confirmed via source→route correlation + oracle)")
        findings += jf

    # Correlate code-location candidates (static / Opengrep / Joern / scanner) to routes, then confirm via oracle.
    if routes:
        from src.pyauto.correlate import correlate
        from src.pyauto.probes import ProbeCtx, confirm_candidates
        pu = urlparse(args.url.rstrip("/"))
        code_cands = [f for f in findings if f.status == "candidate" and f.file not in ("", "(runtime)")]
        bound = correlate(code_cands, routes)
        origin = f"{pu.scheme}://{pu.netloc}"
        ctx = ProbeCtx(origin, auth={}, reseed=None)
        if bound:
            confirm_candidates(bound, ctx)             # the ones with a taint param confirm straight away
            promoted = sum(1 for f in bound if f.status == "confirmed")
            print(f"[correlate] {len(bound)} code candidate(s) mapped to routes; {promoted} CONFIRMED (taint param)")
            # param-less flagged routes: focus the source-fed LLM proposer on JUST those (high-signal) and confirm
            unconf = [f for f in bound if f.status != "confirmed"]
            if unconf and llm and args.target:
                from benchmarks.oracles import Session
                from src.pyauto.llm_attacks import make_source_lookup, propose_candidates
                from src.pyauto.probes import Route
                susp = [Route(s.split(" ", 1)[0], s.split(" ", 1)[1])
                        for s in {f.evidence["route"] for f in unconf}]

                def _fetch(r):
                    try:
                        return Session(origin).request(r.method, r.path).body
                    except Exception:  # noqa: BLE001
                        return ""
                more = propose_candidates(susp, llm, _fetch, source_for=make_source_lookup(args.target),
                                          max_routes=len(susp))
                confirm_candidates(more, ctx)
                newc = [m for m in more if m.status == "confirmed"]
                print(f"[correlate+llm] focused the LLM on {len(susp)} flagged route(s) → {len(newc)} more CONFIRMED")
                findings += newc

                # OOB classes (xxe/ssrf/deserialization) the generic payload couldn't match: let the model
                # SHAPE an app-schema payload; the loopback callback still decides, so precision holds.
                from src.pyauto.llm_attacks import propose_oob_payload
                from src.pyauto.probes import confirm_with_oob_payload
                src_lookup = make_source_lookup(args.target)

                def _payload_for(route, klass):
                    return propose_oob_payload(route, klass, src_lookup(route), _fetch(route), llm)
                oob_cands = unconf + more
                n_oob = confirm_with_oob_payload(oob_cands, ctx, _payload_for)
                if n_oob:
                    print(f"[correlate+llm] LLM-shaped OOB payloads confirmed {n_oob} more")
                    findings += [f for f in oob_cands if f.status == "confirmed" and f not in newc]

    # de-duplicate: the same (class, route/location) can be confirmed via two paths (dynamic + correlate)
    seen_keys, deduped = set(), []
    for f in sorted(findings, key=lambda x: x.status != "confirmed"):   # keep the confirmed copy
        key = (f.klass, f.evidence.get("route") or f"{f.file}:{f.line}")
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(f)
    findings = deduped

    confirmed = [f for f in findings if f.status == "confirmed"]
    print(f"\n== {len(findings)} findings: {len(confirmed)} confirmed, {len(findings) - len(confirmed)} candidate ==")
    for f in sorted(findings, key=lambda x: (x.status != "confirmed", x.klass)):
        where = f.evidence.get("route") or (f"{f.file}:{f.line}" if f.line else f.file)
        print(f"  [{f.status:9}] {f.klass:24} {f.source:7} {where}")
    if args.out:
        from src.jsauto.findings import dump
        dump(findings, args.out, {"coverage": cov} if cov else None)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
