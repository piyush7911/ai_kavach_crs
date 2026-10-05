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
    if "body_regex" in expect and not re.search(expect["body_regex"], resp.body, re.S):
        return False, f"body_regex /{expect['body_regex']}/ not found"
    return True, f"status={resp.status}"


def cmd_score(args) -> int:
    findings = json.loads(Path(args.findings).read_text())
    manifest = json.loads(Path(args.manifest).read_text())
    board = _score(findings, manifest.get("vulns", []))
    _emit(board, args.json)
    return 0


def _score(findings: list, vulns: list) -> dict:
    """Recall/precision by matching a finding to a manifest vuln on same file ± a few lines."""
    matched_vulns, true_pos = set(), 0
    for f in findings:
        hit = next((v for v in vulns if _same_site(f, v) and v["id"] not in matched_vulns), None)
        if hit:
            matched_vulns.add(hit["id"])
            true_pos += 1
    n_find = len(findings) or 1
    n_vuln = len(vulns) or 1
    return {
        "vulns": len(vulns), "findings": len(findings), "true_positives": true_pos,
        "recall": round(true_pos / n_vuln, 3), "precision": round(true_pos / n_find, 3),
        "missed": [v["id"] for v in vulns if v["id"] not in matched_vulns],
    }


def _same_site(finding: dict, vuln: dict) -> bool:
    if Path(finding.get("file", "")).name != Path(vuln.get("file", "")).name:
        return False
    try:
        return abs(int(finding.get("line", -999)) - int(vuln.get("line", 999))) <= 5
    except (TypeError, ValueError):
        return True  # same file, no usable line → count as a site match


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="benchmarks.nodegoat.runner")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start"); s.add_argument("--tree", required=True); s.add_argument("--json")
    s.set_defaults(fn=cmd_start)
    r = sub.add_parser("replay"); r.add_argument("--tree", required=True)
    r.add_argument("--exploit", required=True); r.add_argument("--json"); r.set_defaults(fn=cmd_replay)
    g = sub.add_parser("regress"); g.add_argument("--tree", required=True)
    g.add_argument("--flows"); g.add_argument("--json"); g.set_defaults(fn=cmd_regress)
    c = sub.add_parser("score"); c.add_argument("--findings", required=True)
    c.add_argument("--manifest", required=True); c.add_argument("--patches"); c.add_argument("--json")
    c.set_defaults(fn=cmd_score)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
