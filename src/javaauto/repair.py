"""Autonomous Java repair loop: the model proposes a method, deterministic gates decide.

Same philosophy as the C/JS/Python backends — LLM proposes, gates dispose. Per attempt: ask the model
for the whole fixed method, splice it in by tree-sitter byte range, reject it if it does not parse, REBUILD
and run the patched Spring app on a free port, and replay the confirming exploit. Accepted only when the
exploit no longer reproduces (and any regression flow still passes).

Java can't be copied+run cheaply (a Gradle tree is large and its build cache is path-bound), so the patch
is applied IN PLACE to the source file and the original is always restored in a finally — the tree is
left exactly as found whatever happens.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from benchmarks.oracles import run_exploit
from src.javaauto.patch import find_function_span, parse_errors, replace_function
from src.javaauto.runner import JavaAppServer


@dataclass
class RepairOutcome:
    status: str = "unresolved"          # proven | unresolved | error
    reason: str = ""
    diff: str = ""
    attempts: list = field(default_factory=list)


def extract_function(text: str, name: str) -> str | None:
    for candidate in (text, text.replace("```java", "```").replace("```", "")):
        span = find_function_span(candidate, name)
        if span:
            return candidate[span[0]:span[1]]
    return None


def _prompt(finding: dict, method_src: str) -> str:
    return (
        f"You are fixing a {finding.get('klass','security')} vulnerability (CWE "
        f"{finding.get('cwe','')}) in a Java Spring method named `{finding['function']}`.\n"
        f"{finding.get('guidance','')}\n"
        "Rewrite ONLY this method to fix the vulnerability while preserving behaviour for legitimate "
        "requests. Keep the exact method signature and any annotations (they define the route). Return "
        "just the method, no prose, no markdown.\n\n"
        f"{method_src}\n")


def repair(finding: dict, tree: Path, llm: Callable[[str], str], pov: dict, context_path: str = "",
           regression: list | None = None, attempts: int = 3) -> RepairOutcome:
    out = RepairOutcome()
    target = tree / finding["file"]
    original = target.read_text()
    span = find_function_span(original, finding["function"])
    if span is None:
        out.status, out.reason = "error", f"method {finding['function']!r} not found in {finding['file']}"
        return out
    method_src = original[span[0]:span[1]]

    feedback = ""
    try:
        for n in range(1, attempts + 1):
            att = {"n": n}
            try:
                reply = llm(_prompt(finding, method_src) + (f"\n\nPREVIOUS ATTEMPT REJECTED:\n{feedback}\nFix and answer again." if feedback else ""))
            except Exception as e:  # noqa: BLE001
                out.status, out.reason = "error", f"model call failed: {e}"
                out.attempts.append({**att, "stage": "model", "detail": str(e)[:160]})
                return out
            new_fn = extract_function(reply, finding["function"])
            if not new_fn:
                feedback = "no complete method definition was found in the reply"
                out.attempts.append({**att, "stage": "extract", "detail": feedback})
                continue
            patched = replace_function(original, finding["function"], new_fn)
            errs = parse_errors(patched or "")
            if patched is None or errs:
                feedback = f"the patch does not parse: {errs[:3]}"
                out.attempts.append({**att, "stage": "apply", "detail": feedback})
                continue
            verdict = _gate(tree, target, original, patched, pov, context_path, regression)
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
    finally:
        target.write_text(original)                 # always leave the tree as we found it


def _gate(tree, target, original, patched, pov, context_path, regression):
    """Apply the patch in place, rebuild + run, check the exploit is gone (+ regression), then the caller
    restores the original. Returns (stage, detail)."""
    target.write_text(patched)
    try:
        app = JavaAppServer(tree, context_path=context_path)
        try:
            app.start()
        except Exception as e:  # noqa: BLE001
            return "build", f"patched app did not build/start: {str(e)[:160]}"
        try:
            still, detail = run_exploit(app.base_url, pov)
            if still:
                return "pov", f"the exploit still works: {detail}"
            for flow in (regression or []):
                ok, fdetail = _flow_ok(app.base_url, flow)
                if not ok:
                    return "regression", f"flow {flow.get('name', flow['path'])} broke: {fdetail}"
            return "accepted", "exploit gone" + ("; regression ok" if regression else "")
        finally:
            app.stop()
    finally:
        target.write_text(original)


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
    if "body_regex" in exp and not re.search(exp["body_regex"], r.body, re.S | re.I):
        return False, f"body_regex /{exp['body_regex']}/ not found"
    return True, f"status={r.status}"
