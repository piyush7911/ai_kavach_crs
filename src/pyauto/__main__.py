"""python -m src.pyauto --target DIR [--out findings.json]

Python static detection: generic Kavach Python rules, offline, each hit mapped to its enclosing
function. Emits the shared Finding shape, so the shared runner score step reads it unchanged.
"""
import argparse
import sys
import time

from src.jsauto.findings import dump
from src.pyauto.static import scan


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m src.pyauto")
    p.add_argument("--target", required=True)
    p.add_argument("--out")
    args = p.parse_args(argv)

    t0 = time.time()
    findings = scan(args.target)
    secs = round(time.time() - t0, 1)
    for f in findings:
        print(f"  {f.severity:8} {f.klass:20} {f.file}:{f.line}  ({f.function or '-'})")
    print(f"{len(findings)} finding(s) in {secs}s")
    if args.out:
        dump(findings, args.out, extra={"seconds": secs, "target": args.target})
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
