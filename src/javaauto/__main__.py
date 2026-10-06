"""python -m src.javaauto --target DIR [--out findings.json]

Java static detection: generic Kavach Java rules (Semgrep, offline) mapped to the enclosing method with
tree-sitter-java. Emits the shared Finding shape, so the shared runner/score/report read it unchanged.
"""
import argparse
import sys
import time
from pathlib import Path

from src.javaauto import static
from src.jsauto.findings import dump


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m src.javaauto")
    ap.add_argument("--target", required=True, help="path to the Java source tree")
    ap.add_argument("--out", default="", help="write findings JSON here")
    args = ap.parse_args(argv)
    root = Path(args.target)
    if not root.exists():
        print(f"{root} does not exist", file=sys.stderr)
        return 2
    t0 = time.time()
    findings = static.scan(root)
    seconds = round(time.time() - t0, 2)
    for f in findings:
        where = f"{f.file}:{f.line}" if f.line else f.file
        print(f"{f.id}  {f.severity:8} {f.klass:24} {where:48} {f.function}")
    print(f"\n{len(findings)} finding(s) in {seconds}s")
    if args.out:
        dump(findings, args.out, {"seconds": seconds, "target": str(root)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
