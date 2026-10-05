#!/usr/bin/env python3
"""
Detection precision / recall on labelled good/bad function pairs (Juliet-style).

    python -m tests.benchmarks.detection_eval --corpus PATH [--rules p/security-audit]
        [--split eval|tune|all] [--cwe CWE121,CWE416] [--json out.json]

Labels come from the Juliet naming convention, not from us: a function whose
name contains `bad` (e.g. `CWE121_..._bad`, `badSink`) is a positive; one whose
name starts with `good` (`goodG2B`, `goodB2G1`, `good1`, ...) is a negative.
Functions matching neither are ignored.

A function counts as *flagged* if the detector reports at least one finding
whose start line falls inside it.

Leakage guard: files are split deterministically by sha1 of their relative path
into a `tune` half and an `eval` half. Anything we change about detection
(rule packs, filters) may only be judged on `tune`; the number we publish is
`eval`. The split is fixed by the path hash, so it cannot be chosen after
looking at results.

Our claim is about repair and proof, not detection; this number is reported as
measured, even if it is low.
"""

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from src.autonomy.codeindex import CodeIndex                                     # noqa: E402

BAD = re.compile(r"bad", re.IGNORECASE)
GOOD = re.compile(r"^good", re.IGNORECASE)


def split_of(rel: str) -> str:
    return "eval" if int(hashlib.sha1(rel.encode()).hexdigest(), 16) % 2 else "tune"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(100 * (c - r) / d, 1), round(100 * (c + r) / d, 1))


def label(name: str):
    if GOOD.search(name):
        return False
    if BAD.search(name):
        return True
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--rules", default="p/security-audit")
    ap.add_argument("--split", choices=["eval", "tune", "all"], default="eval")
    ap.add_argument("--cwe", default="", help="comma-separated CWE directory prefixes")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    root = Path(args.corpus).resolve()
    wanted = [c.strip() for c in args.cwe.split(",") if c.strip()]
    files = []
    for p in sorted(root.rglob("*.c")):
        rel = p.relative_to(root).as_posix()
        if wanted and not any(rel.startswith(w) or f"/{w}" in rel for w in wanted):
            continue
        if args.split != "all" and split_of(rel) != args.split:
            continue
        files.append(rel)
    if not files:
        print("no files selected", file=sys.stderr)
        return 2

    index = CodeIndex(root, files, headers=[])
    labelled = []
    for funcs in index.functions.values():
        for f in funcs:
            lab = label(f.name)
            if lab is not None:
                labelled.append((f, lab))

    from src.analysis_engine.semgrep_runner import SemgrepRunner
    runner = SemgrepRunner(rules=args.rules)
    # One scan of the whole corpus; findings are mapped back to selected files.
    selected = set(files)
    flagged_lines: dict[str, set[int]] = {}
    for finding in runner.scan(str(root), max_findings=1_000_000, timeout=3600):
        p = Path(finding.file_path)
        try:
            rel = (p if p.is_absolute() else Path.cwd() / p).resolve().relative_to(root).as_posix()
        except ValueError:
            rel = next((s for s in selected if finding.file_path.endswith(s)), "")
        if rel in selected:
            flagged_lines.setdefault(rel, set()).add(finding.start_line)

    tp = fp = fn = tn = 0
    for f, positive in labelled:
        hit = any(f.start_line <= ln <= f.end_line for ln in flagged_lines.get(f.file, ()))
        if positive and hit:
            tp += 1
        elif positive:
            fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    out = {
        "corpus": str(root), "split": args.split, "rules": args.rules, "files": len(files),
        "functions_labelled": len(labelled), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(100 * precision, 1) if precision is not None else None,
        "precision_95ci_wilson": wilson(tp, tp + fp),
        "recall": round(100 * recall, 1) if recall is not None else None,
        "recall_95ci_wilson": wilson(tp, tp + fn),
    }
    print(json.dumps(out, indent=2))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
