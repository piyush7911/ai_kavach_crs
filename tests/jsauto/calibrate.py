"""
Calibrate the validator against ground truth. LIVE: needs the runner's app stack (MongoDB) and the engine's
findings for the benchmark application.

    python -m tests.jsauto.calibrate --target DIR --runner MODULE --edits calibration_edits.json

If the validator can call a bad patch good, or a good patch bad, every result built on it is worthless. So for each
probe-able class this builds FOUR versions of the application and replays the engine's own generated exploit, its
variants and its benign control against each:

    vulnerable   the original                  primary works, control does not, working variants work
    fixed        a hand-written correct fix    nothing works, the regression flows pass
    overfit      blocks only the exact payload primary stops, a variant still works (hardening must see it)
    gutted       removes the feature entirely  nothing works; the regression flows SHOULD fail (they often cannot)

The edits come from a data file for the one target being calibrated (they are test fixtures, like an answer key), are
applied to a COPY by exact string replacement, and the engine never reads them. A row that does not behave as expected is a bug in the
validator (or, for `gutted`, a gap in the regression flows) and is reported as such, never averaged away.
"""

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

from src.jsauto import probes, static
from src.jsauto import repair as R
from src.jsauto.fix import exploitable

def make_tree(src: Path, dst: Path, edits: dict, klass: str, kind: str) -> Path:
    if dst.exists():
        shutil.rmtree(dst)
    R._copy_tree(src, dst)
    if kind == "vulnerable":
        return dst
    spec = edits[klass]
    path = dst / spec["file"]
    text = path.read_text()
    for old, new in zip(spec["old"], spec[kind]):
        assert old in text, f"calibration edit target not found for {klass}: {old[:50]}"
        text = text.replace(old, new, 1)
    path.write_text(text)
    return dst


def measure(gates, tree: Path, finding: dict) -> dict:
    primary = exploitable(gates, tree, finding["exploit"])[0]
    control = exploitable(gates, tree, probes.control_for(finding))[0]
    variants = [exploitable(gates, tree, v)[0] for v in probes.variants_for(finding)]
    regress = gates.regress(tree)[0]
    return {"primary": primary, "control": control, "variants": variants, "regression": regress}


def judge(klass: str, kind: str, m: dict, vulnerable: dict, blind_spots: dict) -> list[str]:
    """Problems with this measurement, as readable strings (empty = the validator behaved)."""
    out = []
    working = [i for i, v in enumerate(vulnerable["variants"]) if v is True]      # the variants that work on the original
    now = [m["variants"][i] for i in working]
    if kind == "vulnerable":
        if m["primary"] is not True:
            out.append("the primary exploit does NOT work on the vulnerable app (a real bug would never be confirmed)")
        if m["control"] is not False:
            out.append("the benign control triggers the oracle (the oracle fires without an attack)")
        if m["regression"] != R.PASS:
            out.append("the regression flows fail on the untouched app")
    elif kind == "fixed":
        if m["primary"] is not False:
            out.append("a correct fix is still reported exploitable (a good patch would be rejected)")
        if any(v is not False for v in now):
            out.append("a correct fix is reported leaking a variant (a good patch would be rejected by hardening)")
        if m["regression"] != R.PASS:
            out.append("a correct fix fails the regression flows")
    elif kind == "overfit":
        if m["primary"] is not False:
            out.append("the overfitted patch did not even block the primary payload (test setup is wrong)")
        if working and not any(v is True for v in now) and f"{klass}/{kind}" not in blind_spots:
            out.append("an overfitted patch is NOT caught: every variant that works on the original is blocked")
    elif kind == "gutted":
        if m["primary"] is not False or any(v is not False for v in now):
            out.append("test setup is wrong: the gutted tree still lets the exploit through")
        if m["regression"] == R.PASS:
            out.append("GAP: a patch that removes the feature passes the regression flows")
    return out


def run(target: Path, gates, out_dir: Path, edits_file: Path, classes=None) -> dict:
    target, out_dir = Path(target).resolve(), Path(out_dir)
    spec = json.loads(Path(edits_file).read_text())
    edits, blind_spots = spec["classes"], spec.get("blind_spots", {})
    out_dir.mkdir(parents=True, exist_ok=True)
    scan = static.scan(target)
    findings = [f.to_dict() for f in scan["findings"]]
    for i, f in enumerate(findings, 1):
        f["id"] = f"JS-{i:03d}"
    probes.attach(findings)
    by_class = {}
    for f in findings:
        if f["klass"] in edits and f.get("exploit") and f["klass"] not in by_class:
            by_class[f["klass"]] = f
    rows, problems, started = [], [], time.time()
    for klass, f in by_class.items():
        if classes and klass not in classes:
            continue
        print(f"== {klass}: {f['file']}:{f['line']}", flush=True)
        vulnerable = None
        for kind in ("vulnerable", "fixed", "overfit", "gutted"):
            tree = make_tree(target, out_dir / "trees" / f"{klass}-{kind}", edits, klass, kind)
            m = measure(gates, tree, f)
            vulnerable = vulnerable or m
            issues = judge(klass, kind, m, vulnerable, blind_spots)
            blind = blind_spots.get(f"{klass}/{kind}")
            rows.append({"class": klass, "tree": kind, **m, "issues": issues, "known_blind_spot": blind})
            problems += [f"{klass}/{kind}: {x}" for x in issues]
            v = "".join("1" if x else "0" if x is False else "?" for x in m["variants"])
            print(f"   {kind:10} primary={m['primary']!s:5} control={m['control']!s:5} variants={v or '-':8} "
                  f"regress={m['regression']:5} {'OK' if not issues else 'PROBLEM: ' + '; '.join(issues)}", flush=True)
        shutil.rmtree(out_dir / "trees", ignore_errors=True)
    report = {"seconds": round(time.time() - started), "rows": rows, "problems": problems,
              "validator_correct": not [p for p in problems if "GAP" not in p],
              "regression_gaps": [p for p in problems if "GAP" in p]}
    (out_dir / "validator_calibration.json").write_text(json.dumps(report, indent=2))
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tests.jsauto.calibrate")
    ap.add_argument("--target", required=True)
    ap.add_argument("--runner", required=True)
    ap.add_argument("--edits", required=True, help="JSON of hand-fixed / overfitted / gutted edits for the target")
    ap.add_argument("--out", default="reports/js_fix/calibration")
    ap.add_argument("--classes", default="")
    a = ap.parse_args(argv)
    rep = run(Path(a.target), R.RunnerGates(module=a.runner, cwd=Path.cwd()), Path(a.out), Path(a.edits),
              set(filter(None, a.classes.split(","))) or None)
    print(f"\nvalidator correct: {rep['validator_correct']} | problems: {len(rep['problems'])} "
          f"| regression gaps: {len(rep['regression_gaps'])} | {rep['seconds']}s")
    for p in rep["problems"]:
        print("  -", p)
    return 0 if rep["validator_correct"] else 1


if __name__ == "__main__":
    sys.exit(main())
