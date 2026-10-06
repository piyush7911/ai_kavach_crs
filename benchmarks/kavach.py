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
    from src.pyauto.param_discovery import discover_params
    discover_params(origin, routes, ctx)               # chunked binary-search param discovery (fast, 0-FP)
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


_LLM_TRACE_PATH = None   # set from --out: every probe-LLM query/response is appended here for jury audit


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
        import time
        body = json.dumps({"model": model, "temperature": 0, "max_tokens": 1500,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request(f"{base.rstrip('/')}/chat/completions", data=body,
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.load(r)
        reply = data["choices"][0]["message"]["content"] or ""
        if _LLM_TRACE_PATH:                              # RoE §5: LLM query traces retained for jury audit
            try:
                with open(_LLM_TRACE_PATH, "a") as fh:
                    fh.write(json.dumps({"ts": round(t0, 3), "model": model, "ms": round((time.time() - t0) * 1000),
                                         "prompt": prompt, "response": reply}, default=str) + "\n")
            except OSError:
                pass
        return reply
    return llm


def _llm_repair_one(f, args, llm, stack, regression=None):
    """Run the stack's CEGIS repair loop on one confirmed finding; return its RepairOutcome or None. The
    `regression` set (observed benign routes) is the behavior-preservation gate — a patch that changes any
    recorded response is rejected (differential validation, T5)."""
    from pathlib import Path as _P
    finding = {"file": f.file, "function": f.function, "klass": f.klass, "cwe": f.cwe}
    tree = _P(args.target)
    try:
        if stack == "java":
            from urllib.parse import urlparse
            from src.javaauto.repair import repair as jrepair
            return jrepair(finding, tree, llm, f.exploit, context_path=urlparse(args.url).path.rstrip("/"),
                           regression=regression, attempts=2)
        if stack == "python":
            if not args.run_cmd:
                return None
            from src.pyauto.repair import repair as prepair
            return prepair(finding, tree, llm, f.exploit, args.run_cmd, env={},
                           seed_path=args.seed or None, regression=regression, attempts=2)
    except Exception as e:  # noqa: BLE001 — a repair failure must not sink the run
        print(f"   [fix] LLM repair errored on {f.klass} {f.file}: {str(e)[:120]}")
    return None


def _fix_stage(findings, args, _routes_for_fix=None):
    """Template-first (deterministic, no LLM), then CEGIS LLM-fallback for confirmed code-location findings
    with no template. Attaches a verified patch + fix_verification so the reporting gate accepts it."""
    import os
    from pathlib import Path as _P
    from src.autonomy.template_patch import has_template, template_repair
    tcount = 0
    for f in findings:
        tr = template_repair(f.to_dict() if hasattr(f, "to_dict") else {"klass": f.klass, "file": f.file},
                             args.target)
        if tr and tr["status"] == "proven":
            f.patch, f.patch_note = tr["diff"], tr["note"]
            f.fix_verification = f"template re-verified: weak literal removed ({tr['note']})"
            tcount += 1
    print(f"[fix] {tcount} deterministic template patch(es) + verified (no LLM)")
    if not (args.url and os.environ.get("OPENAI_BASE_URL")):
        print("[fix] LLM-fallback skipped (needs --url + OPENAI_BASE_URL; py/js also need --run-cmd)")
        return
    stack = detect_stack(_P(args.target))
    llm = _build_probe_llm()
    cand = [f for f in findings if f.status == "confirmed" and not f.patch and f.exploit
            and f.file and f.file != "(runtime)" and f.function and not has_template(f.klass, f.file)]
    if not cand:
        print("[fix] LLM-fallback: no confirmed code-location findings need it")
        return
    from src.autonomy.differential_validation import regression_from_routes   # observed behavior baseline
    import json as _json
    reg = regression_from_routes(_routes_for_fix, args.url.rstrip("/"),
                                 auth=_json.load(open(args.auth)) if args.auth else None) if _routes_for_fix else []
    print(f"[fix] differential validation: {len(reg)} observed routes form the behavior-preservation gate")
    proven = 0
    for f in cand:
        out = _llm_repair_one(f, args, llm, stack, regression=reg)
        if out and out.status == "proven":
            f.patch, f.patch_note = out.diff, "LLM repair (CEGIS, gated)"
            f.fix_verification = out.reason
            proven += 1
    print(f"[fix] LLM-fallback: {proven}/{len(cand)} confirmed finding(s) patched + proven (gated)")


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
    ap.add_argument("--misuse", action="store_true",
                    help="scan source for FP-safe API-misuse literals (weak hash/cipher/random, cookie "
                         "flags) as confirmed findings; needs --target. Pairs with --fix")
    ap.add_argument("--idor", action="store_true",
                    help="IDOR/BOLA candidate detection from a route map (needs --routes); path-id routes "
                         "are confirmed credential-free via the direct-object-reference oracle")
    ap.add_argument("--smuggle", action="store_true",
                    help="HTTP request-smuggling timing probe (needs --url; isolated-VM only); reports a "
                         "high-confidence CANDIDATE (timing is not a self-validating proof)")
    ap.add_argument("--schema-fuzz", action="store_true",
                    help="auto-fetch the target's OpenAPI spec and flag any 5xx on a schema-valid request "
                         "(confirmed server fault); needs --url")
    ap.add_argument("--live", action="store_true",
                    help="run the language-agnostic live HTTP PROVE oracles (headers/cookies/CORS/JWT/"
                         "rate-limit/enumeration/reflected-XSS/redirect); needs --url")
    ap.add_argument("--routes", help="a route-map JSON (route_map.py output) to drive --live + confirm")
    ap.add_argument("--fix", action="store_true",
                    help="FIX stage: template-first (weak-hash/cookie/random, no LLM), then LLM-fallback "
                         "(CEGIS, gated) for confirmed code-location findings with no template. Needs "
                         "--target; LLM-fallback also needs --url + the LLM endpoint (+ --run-cmd for py/js). "
                         "Dependencies stay report-only")
    ap.add_argument("--auth", help="a JSON auth spec (roles->creds + login shape) to enable authenticated "
                                   "confirmation (authed IDOR/BOLA, live JWT). Shape matches Session's auth")
    ap.add_argument("--run-cmd", default="", help="command to start the app for the LLM-fix gate (py/js)")
    ap.add_argument("--seed", default="", help="seed/reset path hit before each gate attempt (e.g. /createdb)")
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

    global _LLM_TRACE_PATH
    if args.out:                                       # RoE §5 audit: trace every LLM query beside the output
        from pathlib import Path as _P
        _LLM_TRACE_PATH = str(_P(args.out).with_name("llm_trace.jsonl"))
        open(_LLM_TRACE_PATH, "w").close()

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

    if args.live and args.url:                         # language-agnostic HTTP PROVE oracles (FP-safe facts/replays)
        import json as _json
        from src.pyauto.live_probes import live_confirm
        pu = urlparse(args.url.rstrip("/"))
        origin, ctx_path = f"{pu.scheme}://{pu.netloc}", pu.path.rstrip("/")
        if args.routes:                                # a framework route map (any language) drives the oracles best
            rmap = _json.load(open(args.routes)).get("routes", [])
        else:                                          # else fall back to what dynamic discovery found
            rmap = [{"method": r.method, "path": r.path, "file": "", "function": "", "param_annotations": [],
                     "params": list(r.query_fields) + list(r.path_params) + list(r.body_fields),
                     "body": bool(r.body_fields)} for r in routes]
        lf = live_confirm(origin, rmap, ctx=ctx_path)
        from collections import Counter as _C
        print(f"[live] {len(lf)} CONFIRMED via language-agnostic HTTP oracles {dict(_C(f.klass for f in lf))}")
        findings += lf

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
            from src.autonomy import scan_cache
            rules_x = args.opengrep_rules or "default"
            og = scan_cache.load(args.target, "opengrep", rules_x)      # reuse if tree unchanged (sprint re-runs)
            cached = og is not None
            if not cached:
                og = findings_from_opengrep(args.target, rules=_P(args.opengrep_rules) if args.opengrep_rules else None)
                scan_cache.save(args.target, "opengrep", og, rules_x)
            print(f"[opengrep] {len(og)} candidate(s){' (cache hit — tree unchanged)' if cached else ''}")
            findings += og

    if args.joern:
        from benchmarks.scanners.joern import findings_from_joern
        jf = findings_from_joern(args.joern)
        print(f"[joern] {len(jf)} cross-file taint candidate(s) (confirmed via source→route correlation + oracle)")
        findings += jf

    if args.misuse and args.target:
        from benchmarks.scanners.misuse import findings_from_misuse
        mf = findings_from_misuse(args.target)
        from collections import Counter as _Cm
        print(f"[misuse] {len(mf)} FP-safe API-misuse literal(s) confirmed {dict(_Cm(f.klass for f in mf))}")
        findings += mf

    if args.idor and args.routes:
        import json as _json
        from benchmarks.scanners.idor import confirm_idor, findings_from_idor
        auth_spec = _json.load(open(args.auth)) if args.auth else None
        idf = findings_from_idor(args.routes, args.target)
        n_idor = confirm_idor(idf, args.url.rstrip("/"), auth=auth_spec) if args.url else 0
        how = "authenticated + credential-free" if auth_spec else "credential-free"
        print(f"[idor] {len(idf)} IDOR/BOLA candidate(s); {n_idor} CONFIRMED ({how} path-id oracle)")
        findings += idf

    if args.smuggle and args.url:
        from src.pyauto.smuggling import detect_smuggling
        sm = detect_smuggling(args.url.rstrip("/"))
        print(f"[smuggle] {len(sm)} request-smuggling timing candidate(s)")
        findings += sm

    if getattr(args, "schema_fuzz", False) and args.url:
        from src.pyauto.schema_fuzz import schema_fuzz
        sf = schema_fuzz(args.url.rstrip("/"))
        print(f"[schema-fuzz] {len(sf)} schema-valid 5xx server fault(s)")
        findings += sf

    if args.url:                                       # GraphQL surface (only emits if an endpoint exists)
        import json as _j
        from benchmarks.scanners.graphql import findings_from_graphql
        gq = findings_from_graphql(args.url.rstrip("/"), _j.load(open(args.auth)) if args.auth else None)
        if gq:
            print(f"[graphql] {len(gq)} GraphQL BOLA candidate(s) from introspection")
            findings += gq

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

    # DETERMINISTIC route-map bridge (no LLM): exact (file,function)->route from a framework route map +
    # wire param resolved from source (constants included), then our oracle confirms. This is the preferred
    # path when a route map is available — faster, offline, and precise — with the LLM only a fallback.
    if args.routes and args.target and args.url:
        from src.pyauto.correlate import correlate_with_routemap
        from src.pyauto.param_source import build_param_lookup
        from src.pyauto.probes import ProbeCtx, confirm_candidates
        base = args.url.rstrip("/")                    # full base incl. any context path (e.g. /VulnerableApp)
        rctx = ProbeCtx(base, auth={}, reseed=None)
        code_cands = [f for f in findings if f.status == "candidate" and f.file not in ("", "(runtime)")]
        rb = correlate_with_routemap(code_cands, args.routes, build_param_lookup(args.target))
        if rb:
            confirm_candidates(rb, rctx)
            newd = [f for f in rb if f.status == "confirmed"]
            print(f"[routemap] {len(rb)} candidate(s) mapped+param'd deterministically; {len(newd)} CONFIRMED (no LLM)")
            findings += newd

    # candidate sanity (Shannon #12/#13): drop static candidates whose cited file:line/function does not
    # exist (hallucination), demote injection candidates with no ingress. Confirmed findings are exempt.
    if args.target:
        from src.autonomy.candidate_sanity import sanity
        kept, dropped = [], 0
        for f in findings:
            verdict, reason = sanity(f.to_dict() if hasattr(f, "to_dict") else {"klass": f.klass,
                                     "file": f.file, "line": f.line, "function": f.function,
                                     "status": f.status, "evidence": f.evidence}, args.target)
            if verdict == "drop":
                dropped += 1
                continue
            if verdict == "demote":
                f.confidence = "low"
            kept.append(f)
        if dropped:
            print(f"[sanity] dropped {dropped} candidate(s) with a hallucinated/invalid source location")
        findings = kept

    # de-duplicate: the same (class, route/location) can be confirmed via two paths (dynamic + correlate)
    seen_keys, deduped = set(), []
    for f in sorted(findings, key=lambda x: x.status != "confirmed"):   # keep the confirmed copy
        key = (f.klass, f.evidence.get("route") or f"{f.file}:{f.line}")
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(f)
    findings = deduped

    # FIX stage (deterministic, template-first): for findings with a safe template, produce a verified
    # mechanical patch — no LLM. Classes without a template are left for the LLM repair loop; dependencies
    # are never version-bumped (report-only). Needs the source tree (--target).
    if args.fix and args.target:
        _fix_stage(findings, args, routes)

    # REPORTING GATE (FP-zero contract): a finding may stay `confirmed`/claimed only if it carries proof +
    # self-critique (poc/evidence, counterevidence, confidence+rationale, severity conditions, and
    # fix_verification when patched). Fill deterministically from the oracle; downgrade any that can't.
    from src.autonomy.finding_gate import gate_finding
    downgraded = 0
    for f in findings:
        ok, errs = gate_finding(f)
        if f.status == "confirmed" and not ok:
            f.status = "candidate"
            f.reason = f"(gate) downgraded — not claimable: {errs[0]}"
            downgraded += 1
    if downgraded:
        print(f"[gate] {downgraded} finding(s) downgraded confirmed→candidate (failed the reporting gate)")

    confirmed = [f for f in findings if f.status == "confirmed"]
    print(f"\n== {len(findings)} findings: {len(confirmed)} confirmed, {len(findings) - len(confirmed)} candidate ==")
    for f in sorted(findings, key=lambda x: (x.status != "confirmed", x.klass)):
        where = f.evidence.get("route") or (f"{f.file}:{f.line}" if f.line else f.file)
        print(f"  [{f.status:9}] {f.klass:24} {f.source:7} {where}")
    if args.out:
        from pathlib import Path as _P
        from src.autonomy.exchange_log import ExchangeLog
        xlog = ExchangeLog(str(_P(args.out).with_name("exchanges.jsonl")))   # audit record of attack traffic
        for f in findings:
            if f.status == "confirmed" and f.exploit:
                ex = f.exploit
                inner = (ex.get("differential") or ex.get("idor") or ex.get("access_control")
                         or ex.get("write_idor") or {})
                req = inner.get("true_request") or inner.get("request") or inner.get("foreign_request") or ex
                rid = xlog.record(req.get("method", "GET"), req.get("path", ""),
                                  200, req=req, resp_preview=f.reason)
                f.http_exchange_ids = [rid]
        from src.jsauto.findings import dump
        dump(findings, args.out, {"coverage": cov} if cov else None)
        print(f"wrote {args.out}")
        if routes:                                     # evidenced coverage ledger beside the findings
            from pathlib import Path as _P
            from src.autonomy.coverage_ledger import ledger_from_run
            ledger = ledger_from_run(routes, findings)
            lpath = str(_P(args.out).with_name("coverage.json"))
            ledger.dump(lpath)
            print(f"[coverage] ledger: {ledger.counts()} -> {lpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
