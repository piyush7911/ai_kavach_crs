"""Autonomous Python repair loop: the model proposes a function, deterministic gates decide.

Per attempt: ask the model for the whole fixed function, splice it in by AST byte range, reject it
if it does not parse, run the PATCHED app on a free port, and replay the confirming exploit. The
patch is accepted only when the exploit no longer reproduces (and, where given, a regression check
still passes). Every rejection is fed back. Same philosophy as the C/JS backends; only the splicer,
parser and runner are Python.
"""
from __future__ import annotations

import difflib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from benchmarks.oracles import run_exploit
from src.pyauto.patch import find_function_span, parse_errors, replace_function
from src.pyauto.runner import PyAppServer


@dataclass
class RepairOutcome:
    status: str = "unresolved"          # proven | unresolved | error
    reason: str = ""
    diff: str = ""
    attempts: list = field(default_factory=list)


def extract_function(text: str, name: str) -> str | None:
    """Pull `def name(...)` out of a model reply (handles ``` fences and surrounding prose) using
    the same AST span logic the splice uses, so what we extract is exactly what will apply."""
    for candidate in (text, text.replace("```python", "```").replace("```py", "```").replace("```", "")):
        span = find_function_span(candidate, name)
        if span:
            return candidate[span[0]:span[1]]
    return None


def _prompt(finding: dict, function_src: str) -> str:
    return (
        f"You are fixing a {finding.get('klass','security')} vulnerability (CWE "
        f"{finding.get('cwe','')}) in a Python web handler named `{finding['function']}`.\n"
        f"{finding.get('guidance','')}\n"
        "Rewrite ONLY this function to fix the vulnerability while preserving behaviour for "
        "legitimate requests. Return just the function definition, no prose.\n\n"
        f"{function_src}\n")


def repair(finding: dict, tree: Path, llm: Callable[[str], str], pov: dict,
           run_cmd: str, env: dict, seed_path: str | None, health_path: str = "/",
           regression: list | None = None, attempts: int = 3) -> RepairOutcome:
    out = RepairOutcome()
    target_file = tree / finding["file"]
    original = target_file.read_text()
    span = find_function_span(original, finding["function"])
    if span is None:
        out.status, out.reason = "error", f"function {finding['function']!r} not found in {finding['file']}"
        return out
    function_src = original[span[0]:span[1]]

    feedback = ""
    for n in range(1, attempts + 1):
        att = {"n": n}
        try:
            reply = llm(_prompt(finding, function_src) + (f"\n\nPREVIOUS ATTEMPT REJECTED:\n{feedback}\nFix and answer again." if feedback else ""))
        except Exception as e:  # noqa: BLE001
            out.status, out.reason = "error", f"model call failed: {e}"
            out.attempts.append({**att, "stage": "model", "detail": str(e)[:160]})
            return out
        new_fn = extract_function(reply, finding["function"])
        if not new_fn:
            feedback = "no complete function definition was found in the reply"
            out.attempts.append({**att, "stage": "extract", "detail": feedback})
            continue
        patched = replace_function(original, finding["function"], new_fn)
        errs = parse_errors(patched or "")
        if patched is None or errs:
            feedback = f"the patch does not parse: {errs[:3]}"
            out.attempts.append({**att, "stage": "apply", "detail": feedback})
            continue
        verdict = _gate(tree, target_file, patched, pov, run_cmd, env, seed_path, health_path, regression)
        out.attempts.append({**att, "stage": verdict[0], "detail": verdict[1]})
        if verdict[0] == "accepted":
            out.status = "proven"
            out.reason = "exploit no longer reproduces" + ("; regression ok" if regression else "")
            out.diff = "".join(difflib.unified_diff(original.splitlines(keepends=True),
                                                     patched.splitlines(keepends=True),
                                                     finding["file"], finding["file"]))
            return out
        feedback = verdict[1]
    out.reason = f"no attempt passed in {attempts} tries; last: {feedback}"
    return out


def _gate(tree, target_file, patched, pov, run_cmd, env, seed_path, health_path, regression):
    """Run the patched tree and check the exploit is gone (+ regression). Returns (stage, detail)."""
    work = Path(tempfile.mkdtemp(prefix="pyrepair_"))
    try:
        patched_tree = work / "tree"
        shutil.copytree(tree, patched_tree)
        (patched_tree / target_file.relative_to(tree)).write_text(patched)
        app = PyAppServer(patched_tree, run_cmd, env=env, seed_path=seed_path, health_path=health_path)
        try:
            app.start()
        except Exception as e:  # noqa: BLE001
            return "start", f"patched app did not start: {e}"
        try:
            still, detail = run_exploit(app.base_url, pov)
            if still:
                return "pov", f"the exploit still works: {detail}"
            for flow in (regression or []):
                ok, fdetail = _flow_ok_stable(app.base_url, flow)
                if not ok:
                    return "regression", f"flow {flow.get('name', flow['path'])} broke: {fdetail}"
            return "accepted", "exploit gone" + ("; regression ok" if regression else "")
        finally:
            app.stop()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _flow_ok_stable(base_url, flow, tries: int = 3):
    """A regression flow that passes on ANY try is not a regression. Transient flakiness (a slow DB,
    a one-off login/network hiccup) otherwise rejects a correct patch; only a flow that fails every try
    is counted a break. Adapted from bug-hunter's two-run flaky baseline (MIT, codexstar69): same intent,
    applied to our live HTTP flows instead of a unit suite."""
    import time
    ok, detail = False, "not run"
    for i in range(tries):
        ok, detail = _flow_ok(base_url, flow)
        if ok:
            return True, detail
        if i < tries - 1:
            time.sleep(0.5)
    return False, detail + f" (failed {tries}/{tries} tries)"


def _flow_ok(base_url, flow):
    import re
    from benchmarks.oracles import Session
    s = Session(base_url, follow_redirects=bool(flow.get("follow_redirects")), auth=flow.get("auth"))
    if not s.login(flow.get("login_as", "none")):
        return False, "login failed"
    r = s.request(flow.get("method", "GET"), flow["path"], headers=flow.get("headers"), body=flow.get("body"))
    exp = flow.get("expect", {})
    if "status" in exp and r.status != exp["status"]:
        return False, f"status {r.status} != {exp['status']}"
    if "status_lt" in exp and r.status >= exp["status_lt"]:   # "served, not denied/broken" (owner path)
        return False, f"status {r.status} not < {exp['status_lt']}"
    if "body_regex" in exp and not re.search(exp["body_regex"], r.body, re.S | re.I):
        return False, f"body_regex /{exp['body_regex']}/ not found"
    return True, f"status={r.status}"
