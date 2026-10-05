"""python -m src.jsauto --target DIR [--out findings.json] [--no-deps]"""

import argparse
import sys
import time
from pathlib import Path

from src.jsauto import deps, static
from src.jsauto.findings import dump


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m src.jsauto")
    ap.add_argument("--target", required=True, help="path to the Node application")
    ap.add_argument("--out", default="", help="write findings JSON here")
    ap.add_argument("--no-deps", action="store_true", help="skip the dependency audit (needs network)")
    args = ap.parse_args(argv)
    root = Path(args.target)
    if not (root / "package.json").exists():
        print(f"{root} has no package.json: not a Node application", file=sys.stderr)
        return 2

    t0 = time.time()
    s = static.scan(root)
    d = {"findings": [], "error": "skipped (--no-deps)", "totals": {}} if args.no_deps else deps.audit(root)
    findings = s["findings"] + d["findings"]
    for i, f in enumerate(findings, 1):
        f.id = f"JS-{i:03d}"
    seconds = round(time.time() - t0, 2)
    for f in findings:
        where = f"{f.file}:{f.line}" if f.line else f.file
        print(f"{f.id}  {f.severity:8} {f.klass:24} {where:36} {f.function or f.evidence.get('package', '')}")
    print(f"\n{len(findings)} finding(s) in {seconds}s | suppressed: {len(s['suppressed'])} "
          f"| dependency audit: {d['error'] or 'ok'} | semgrep errors: {len(s['semgrep_errors'])}")
    if s.get("classifier_errors"):
        print(f"WARNING: {len(s['classifier_errors'])} classifier call(s) failed, e.g. {s['classifier_errors'][0]}",
              file=sys.stderr)
    if args.out:
        dump(findings, args.out, {"suppressed": [x.to_dict() for x in s["suppressed"]],
                                  "dependency_audit_error": d["error"], "dependency_totals": d["totals"],
                                  "semgrep_errors": s["semgrep_errors"], "seconds": seconds,
                                  "target": str(root)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
