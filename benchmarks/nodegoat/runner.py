"""Track-1 runner: start / replay / regress / score for a Node web-app tree.

Each command starts the given tree in isolation (own port, own DB, loopback only),
does one job, and tears it down — so every invocation maps cleanly onto the DRV
loop's build_command / pov_command / test_command templates. The engine (Track 2)
calls these; it never imports the manifest.

    python -m benchmarks.nodegoat.runner start   --tree DIR [--json out.json]
    python -m benchmarks.nodegoat.runner replay  --tree DIR --exploit E.json
    python -m benchmarks.nodegoat.runner regress  --tree DIR [--flows flows.json]
    python -m benchmarks.nodegoat.runner score    --findings F.json --manifest M.json [--patches DIR]

Exit codes:
    start   : 0 healthy, 1 failed to come up
    replay  : 0 NOT exploitable (safe/fixed), 1 exploitable, 2 error
    regress : 0 all flows match golden, 1 a flow diverged, 2 no golden/error
    score   : 0 always (writes a scoreboard)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .appserver import AppServer
from .exploit import Session, run_exploit

HERE = Path(__file__).resolve().parent
DEFAULT_FLOWS = HERE / "flows.json"


def _emit(obj: dict, path: str | None) -> None:
    text = json.dumps(obj, indent=2)
    if path:
        Path(path).write_text(text)
    print(text)


def cmd_start(args) -> int:
    app = AppServer(Path(args.tree).resolve())
    try:
        app.start()
    except Exception as e:  # noqa: BLE001 - report any boot failure as data
        _emit({"ok": False, "error": str(e)}, args.json)
        return 1
    _emit({"ok": True, "base_url": app.base_url, "port": app.port,
           "db": app.db_name, "boot_seconds": app.boot_seconds}, args.json)
    app.stop()
    return 0


def cmd_replay(args) -> int:
    exploit = json.loads(Path(args.exploit).read_text())
    app = AppServer(Path(args.tree).resolve())
    try:
        app.start()
    except Exception as e:  # noqa: BLE001
        _emit({"error": f"app failed to start: {e}"}, args.json)
        return 2
    try:
        exploitable, detail = run_exploit(app.base_url, exploit)
    finally:
        app.stop()
    _emit({"exploitable": exploitable, "detail": detail,
           "exploit": args.exploit}, args.json)
    return 1 if exploitable else 0


def cmd_regress(args) -> int:
    flows_path = Path(args.flows) if args.flows else DEFAULT_FLOWS
    if not flows_path.exists():
        _emit({"error": f"no golden flows at {flows_path}; record them first (task 1.5)"}, args.json)
        return 2
    flows = json.loads(flows_path.read_text())
    app = AppServer(Path(args.tree).resolve())
    try:
        app.start()
    except Exception as e:  # noqa: BLE001
        _emit({"error": f"app failed to start: {e}"}, args.json)
        return 2
    results, ok = [], True
    try:
        for flow in flows:
            passed, detail = _check_flow(app.base_url, flow)
            ok = ok and passed
            results.append({"name": flow.get("name", flow["path"]), "pass": passed, "detail": detail})
    finally:
        app.stop()
    _emit({"ok": ok, "flows": results}, args.json)
    return 0 if ok else 1


def _check_flow(base_url: str, flow: dict) -> tuple[bool, str]:
    sess = Session(base_url, follow_redirects=bool(flow.get("follow_redirects")))
    if not sess.login(flow.get("login_as", "none")):
        return False, "login failed"
    resp = sess.request(flow.get("method", "GET"), flow["path"],
                        headers=flow.get("headers"), body=flow.get("body"))
    expect = flow.get("expect", {})
    if "status" in expect and resp.status != expect["status"]:
        return False, f"status {resp.status} != {expect['status']}"
    import re
    if "body_regex" in expect and not re.search(expect["body_regex"], resp.body, re.S | re.I):
        return False, f"body_regex /{expect['body_regex']}/ not found"
    if "redirect_regex" in expect and not re.search(expect["redirect_regex"], resp.location):
        return False, f"redirect /{expect['redirect_regex']}/ not in Location={resp.location!r}"
    return True, f"status={resp.status}"


def cmd_harden(args) -> int:
    """Replay a vuln's primary PoV plus its variants (alternate encodings of the same
    attack). A correct fix defeats all of them; a fix that only special-cases the
    primary input is 'overfitted'. The web analogue of re-fuzzing a C patch.

    Verdict: vulnerable (primary still exploitable), overfitted (primary safe but a
    variant exploitable), hardened (primary + every variant safe).
    Exit: 0 hardened, 1 overfitted, 2 vulnerable or error.
    """
    manifest = json.loads(Path(args.manifest).read_text())
    vuln = next((v for v in manifest["vulns"] if v["id"] == args.id), None)
    if not vuln or not vuln.get("pov"):
        _emit({"error": f"no vuln/pov for id {args.id}"}, args.json)
        return 2
    base = Path(args.manifest).resolve().parent
    primary = json.loads((base / vuln["pov"]).read_text())
    variants = [(p, json.loads((base / p).read_text())) for p in vuln.get("variants", [])]

    app = AppServer(Path(args.tree).resolve())
    try:
        app.start()
    except Exception as e:  # noqa: BLE001
        _emit({"error": f"app failed to start: {e}"}, args.json)
        return 2
    try:
        p_exploitable, p_detail = run_exploit(app.base_url, primary)
        results = []
        for path, ex in variants:
            ex_hit, detail = run_exploit(app.base_url, ex)
            results.append({"variant": path, "exploitable": ex_hit, "detail": detail})
    finally:
        app.stop()

    leaked = [r["variant"] for r in results if r["exploitable"]]
    if p_exploitable:
        verdict = "vulnerable"
    elif leaked:
        verdict = "overfitted"
    else:
        verdict = "hardened"
    _emit({"id": args.id, "verdict": verdict, "primary_exploitable": p_exploitable,
           "primary_detail": p_detail, "variants_leaked": leaked, "variants": results}, args.json)
    return {"hardened": 0, "overfitted": 1, "vulnerable": 2}[verdict]


def cmd_score(args) -> int:
    raw = json.loads(Path(args.findings).read_text())
    findings = raw["findings"] if isinstance(raw, dict) else raw  # accept {findings:[...]} or [...]
    manifest = json.loads(Path(args.manifest).read_text())
    board = _score(findings, manifest.get("vulns", []))
    _emit(board, args.json)
    return 0


def _score(findings: list, vulns: list) -> dict:
    """Recall and precision of the engine's findings against the manifest answer key.

    recall    = distinct manifest vulns hit / total vulns
    precision = finding GROUPS (same file+class) that hit a real vuln / total groups
    Findings the engine marked informational/suppressed (e.g. a password in a seed
    script) are not defects, so they are excluded from precision but still reported.
    Grouping by (file, class) stops N vulnerable-dependency findings on package.json
    from each counting separately. Matching is file+line (CONTRACT.md explains why).
    """
    scored = [f for f in findings if f.get("status") not in ("informational", "suppressed")]
    excluded = len(findings) - len(scored)

    matched_vulns = set()
    for f in scored:
        hit = _best_match(f, vulns)
        if hit:
            matched_vulns.add(hit["id"])

    groups: dict = {}
    for f in scored:
        key = (Path(f.get("file", "")).name, f.get("klass") or f.get("class") or "")
        groups.setdefault(key, []).append(f)
    precise_groups = sum(1 for g in groups.values() if any(_best_match(f, vulns) for f in g))

    n_grp = len(groups) or 1
    n_vuln = len(vulns) or 1
    return {
        "vulns": len(vulns), "findings": len(findings), "scored": len(scored),
        "informational_excluded": excluded, "finding_groups": len(groups),
        "true_positives": len(matched_vulns),
        "recall": round(len(matched_vulns) / n_vuln, 3),
        "precision": round(precise_groups / n_grp, 3),
        "found": sorted(matched_vulns),
        "missed": [v["id"] for v in vulns if v["id"] not in matched_vulns],
    }


def _best_match(finding: dict, vulns: list) -> dict | None:
    """Among manifest vulns in the same file+line window, prefer a CWE match, then a
    class match, then the first. Breaks ties when two vulns sit close in one file."""
    cands = [v for v in vulns if _same_site(finding, v)]
    if not cands:
        return None
    fc = finding.get("klass") or finding.get("class") or ""
    fcwe = finding.get("cwe", "")
    return (next((v for v in cands if fcwe and v.get("cwe") == fcwe), None)
            or next((v for v in cands if fc and v.get("class") == fc), None)
            or cands[0])


def _same_site(finding: dict, vuln: dict) -> bool:
    if Path(finding.get("file", "")).name != Path(vuln.get("file", "")).name:
        return False
    try:
        fl, vl = int(finding.get("line", 0)), int(vuln.get("line", 0))
    except (TypeError, ValueError):
        return True
    if fl <= 0 or vl <= 0:
        return True  # a line of 0 means "whole file" (config, dependencies)
    return abs(fl - vl) <= 5


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="benchmarks.nodegoat.runner")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start"); s.add_argument("--tree", required=True); s.add_argument("--json")
    s.set_defaults(fn=cmd_start)
    r = sub.add_parser("replay"); r.add_argument("--tree", required=True)
    r.add_argument("--exploit", required=True); r.add_argument("--json"); r.set_defaults(fn=cmd_replay)
    g = sub.add_parser("regress"); g.add_argument("--tree", required=True)
    g.add_argument("--flows"); g.add_argument("--json"); g.set_defaults(fn=cmd_regress)
    h = sub.add_parser("harden"); h.add_argument("--tree", required=True)
    h.add_argument("--id", required=True); h.add_argument("--manifest", default=str(HERE / "manifest.json"))
    h.add_argument("--json"); h.set_defaults(fn=cmd_harden)
    c = sub.add_parser("score"); c.add_argument("--findings", required=True)
    c.add_argument("--manifest", required=True); c.add_argument("--patches"); c.add_argument("--json")
    c.set_defaults(fn=cmd_score)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
