"""
Find, confirm, repair and harden every fixable finding in a Node application, then re-check the result.

    python -m src.jsauto.fix --target DIR --runner some.runner.module [--out DIR] [--attempts 3]

The cycle, per finding, on a COPY of the application that accumulates accepted patches (so a later fix is
made against the code that earlier fixes produced, and one fix can make another unnecessary):

  1. CONFIRM. The probe's exploit is replayed against the unpatched application. Only an exploit that
     really works counts as a proof of vulnerability; one that does not reproduce is dropped and the
     finding is repaired without a PoV gate, so it can never be reported as `proven`.
  2. VARIANTS. Other spellings of the exploit are replayed too, and only the ones that work on the
     unpatched code are kept (a variant that never worked would "pass" any patch and prove nothing).
  3. REPAIR. The model proposes a fix for the flagged function; it is spliced, vetted by the patch policy,
     and run through the start, proof-of-vulnerability, regression and hardening gates (repair.py).
  4. After all findings: the final tree is started, the regression flows are run, and every confirmed
     exploit is replayed against it.

Nothing here knows an application. The application's start / replay / regress commands come from the
runner given on the command line (or KAVACH_RUNNER_MODULE). The runner's manifest is never read.

Outputs in --out: evidence.json (one entry per finding with status and reason), patches/<id>.diff,
final.diff (everything that changed), combined/ (the patched tree), and the model trace if
KAVACH_LLM_TRACE is set.
"""

import argparse
import difflib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from src.jsauto import probes
from src.jsauto import repair as R

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Classes where no edit to the application's code is the fix, with the reason that is recorded.
NOT_A_CODE_EDIT = {
    "private-key-in-repo": "the key is exposed by being in the repository: it must be removed from the "
                           "repository and rotated, which a code edit cannot do",
}


def exploitable(gates, tree: Path, exploit: dict) -> tuple[Optional[bool], str]:
    """True/False if the exploit works against `tree`, None if that could not be determined."""
    fn = getattr(gates, "exploitable", None)
    if fn is not None:
        return fn(tree, exploit)
    state, detail = gates.replay(tree, exploit)
    return (state == R.FAIL and detail.startswith("still exploitable")), detail


def _scan(target: Path, llm, out: Path) -> list[dict]:
    from src.jsauto import deps, static
    result = static.scan(target, llm=llm, learned_path=out / "classified_calls.json")
    found = list(result["findings"]) + deps.audit(target)["findings"]
    dicts = [f.to_dict() for f in found]
    for i, d in enumerate(dicts, 1):
        d["id"] = f"JS-{i:03d}"
    return dicts


def run(target: Path, gates, llm, out_dir: Path, findings: Optional[list] = None, attempts: int = 3,
        max_findings: int = 0, classes: Optional[set] = None,
        on_event: Callable[[str, str], None] = lambda k, m: None) -> dict:
    started = time.time()
    target, out = Path(target).resolve(), Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "patches").mkdir(exist_ok=True)
    calls_before = len(getattr(llm, "usage_log", []))

    if findings is None:
        on_event("scan", f"scanning {target}")
        findings = _scan(target, llm, out)
    probes.attach(findings)
    queue = [f for f in findings if f.get("status") not in ("informational", "suppressed")
             and (not classes or f["klass"] in classes)]
    queue.sort(key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "medium"), 2), f["id"]))
    if max_findings:
        queue = queue[:max_findings]

    combined = out / "combined"
    if combined.exists():
        shutil.rmtree(combined, ignore_errors=True)
    R._copy_tree(target, combined)
    changed: dict[str, str] = {}                       # file -> original text, for the final diff
    entries = []

    for n, f in enumerate(queue, 1):
        e = {"id": f["id"], "klass": f["klass"], "severity": f.get("severity"), "file": f["file"],
             "function": f.get("function", ""), "confirmed": None, "variants": {"kept": 0, "of": 0}}
        t0 = time.time()
        on_event("finding", f"[{n}/{len(queue)}] {f['id']} {f['klass']} {f['file']}:{f.get('function', '')}")
        entries.append(e)
        if f["klass"] in NOT_A_CODE_EDIT:
            e.update(status="not_a_code_fix", reason=NOT_A_CODE_EDIT[f["klass"]])
            continue

        exploit, variants = f.get("exploit"), []
        if exploit:
            on_original, detail = exploitable(gates, target, exploit)
            e["confirmed"] = bool(on_original)
            if on_original:
                now, _ = exploitable(gates, combined, exploit)       # an earlier patch may have fixed it already
                if now is False:
                    e.update(status="already_fixed", reason="the exploit worked on the original application but "
                                                            "no longer works after the earlier patches")
                    continue
                every = probes.variants_for(f)
                e["variants"]["of"] = len(every)
                variants = [v for v in every if exploitable(gates, combined, v)[0] is True]
                e["variants"]["kept"] = len(variants)
            else:
                e["unconfirmed_reason"] = ("the exploit did not reproduce on the unpatched application"
                                           if on_original is False else f"the runner could not tell: {detail[:120]}")
                exploit = None                                        # no PoV gate: it could never be `proven`
        work_finding = {**f, "exploit": exploit}
        outcome = R.repair(work_finding, combined, llm, gates, max_attempts=attempts, variants=variants,
                           on_event=on_event)
        e.update(status=outcome.status, reason=outcome.reason, hardened=outcome.hardened,
                 gates=outcome.gates, attempts=[a.__dict__ for a in outcome.attempts])
        if outcome.new_text:
            path = combined / outcome.file
            changed.setdefault(outcome.file, path.read_text(errors="replace"))
            path.write_text(outcome.new_text)
            (out / "patches" / f"{f['id']}.diff").write_text(outcome.diff)
            e["patch"] = f"patches/{f['id']}.diff"
        e["seconds"] = round(time.time() - t0, 1)
        on_event("result", f"{f['id']}: {outcome.status}" + (" (hardened)" if outcome.hardened else ""))

    final = _final_check(combined, gates, [(f, e) for f, e in zip(queue, entries) if e.get("confirmed")])
    (out / "final.diff").write_text("".join(
        "".join(difflib.unified_diff(before.splitlines(keepends=True),
                                     (combined / name).read_text(errors="replace").splitlines(keepends=True),
                                     fromfile="a/" + name, tofile="b/" + name))
        for name, before in sorted(changed.items())))

    counts: dict[str, int] = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    evidence = {
        "target": str(target), "seconds": round(time.time() - started, 1), "attempts_per_finding": attempts,
        "findings_total": len(findings), "attempted": len(entries), "by_status": counts,
        "model_calls": len(getattr(llm, "usage_log", [])) - calls_before,
        "llm_trace": os.getenv("KAVACH_LLM_TRACE", ""), "final_check": final, "findings": entries,
        "skipped": [{"id": f["id"], "klass": f["klass"], "status": f.get("status", "candidate")}
                    for f in findings if f not in queue]}
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2))
    return evidence


def _final_check(tree: Path, gates, confirmed: list) -> dict:
    """The patched tree as a whole: does it start, do the flows pass, are the exploits blocked?"""
    start, start_detail = gates.start(tree)
    regress, regress_detail = gates.regress(tree)
    blocked, leaked = [], []
    for f, e in confirmed:
        works, _ = exploitable(gates, tree, f["exploit"]) if f.get("exploit") else (None, "")
        (blocked if works is False else leaked).append(f["id"])
    return {"start": start, "start_detail": start_detail[:200], "regression": regress,
            "regression_detail": regress_detail[:200], "confirmed_exploits_blocked": blocked,
            "confirmed_exploits_still_working": leaked}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m src.jsauto.fix")
    ap.add_argument("--target", required=True)
    ap.add_argument("--runner", default=os.getenv("KAVACH_RUNNER_MODULE", ""),
                    help="Python module implementing start/replay/regress (or set KAVACH_RUNNER_MODULE)")
    ap.add_argument("--out", default="reports/js_fix")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--max-findings", type=int, default=0, help="0 = all")
    ap.add_argument("--classes", default="", help="comma list, e.g. open-redirect,eval-injection")
    ap.add_argument("--findings", default="", help="use this findings JSON instead of scanning")
    args = ap.parse_args(argv)

    from src.agent_orchestrator.llm_client import LLMClient
    llm = LLMClient()
    gates = R.RunnerGates(module=args.runner or None, cwd=Path.cwd())
    findings = json.loads(Path(args.findings).read_text())["findings"] if args.findings else None
    ev = run(Path(args.target), gates, llm, Path(args.out), findings=findings, attempts=args.attempts,
             max_findings=args.max_findings, classes=set(filter(None, args.classes.split(","))) or None,
             on_event=lambda k, m: print(f"  {k:8} {m}", flush=True))
    print(f"\n{ev['attempted']} finding(s) attempted in {ev['seconds']}s, {ev['model_calls']} model call(s)")
    for status, n in sorted(ev["by_status"].items()):
        print(f"  {status:18} {n}")
    fc = ev["final_check"]
    print(f"final tree: start={fc['start']} regression={fc['regression']} "
          f"exploits blocked={len(fc['confirmed_exploits_blocked'])} "
          f"still working={len(fc['confirmed_exploits_still_working'])}")
    print(f"evidence: {Path(args.out) / 'evidence.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
