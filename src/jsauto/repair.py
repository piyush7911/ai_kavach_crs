"""
Repair one JavaScript finding: ask the model, splice and vet its answer, run the gates, and feed every
rejection back until a patch passes or the attempts run out.

Gates are tri-state, like everywhere else in the project: "pass", "fail" or "skipped". A gate that did not
run is `skipped` and never counts as a pass. Concretely, a finding with no replayable exploit has its
proof-of-vulnerability gate skipped, so its patch can be at best `patched_unproven`, not `proven`.

The gates themselves are injected (`Gates`), so this module is testable with stubs and the runner that
starts the target application stays a separate concern. `RunnerGates` calls a runner's CLI; which runner is
a setting (`KAVACH_RUNNER_MODULE`), never something the engine knows about.

    start    -> does the patched tree come up healthy?
    replay   -> is the exploit still effective?   (pass = no longer exploitable)
    regress  -> do the application's own flows still match?

What the loop never does: edit anything but the flagged function, trust the answer to parse, or accept a
patch the policy refused (see patch.py).
"""

import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Protocol

from src.jsauto import context, patch

PASS, FAIL, SKIPPED = "pass", "fail", "skipped"


class Gates(Protocol):
    def start(self, tree: Path) -> tuple[str, str]: ...
    def replay(self, tree: Path, exploit: dict) -> tuple[str, str]: ...
    def regress(self, tree: Path) -> tuple[str, str]: ...


@dataclass
class Attempt:
    number: int
    stage: str = ""                 # generation | apply | policy | start | pov | regression | accepted
    detail: str = ""
    seconds: float = 0.0


@dataclass
class RepairOutcome:
    status: str = "unresolved"      # proven | patched_unproven | unresolved | error
    reason: str = ""
    attempts: list = field(default_factory=list)
    gates: dict = field(default_factory=dict)
    diff: str = ""
    file: str = ""
    seconds: float = 0.0

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["attempts"] = [a.__dict__ for a in self.attempts]
        return d


def _copy_tree(src: Path, dst: Path) -> None:
    """A working copy of the application. node_modules is linked, not copied: it is large and read-only."""
    def ignore(_dir, names):
        return [n for n in names if n in ("node_modules", ".git")]
    shutil.copytree(src, dst, ignore=ignore, symlinks=False)
    nm = src / "node_modules"
    if nm.exists():
        (dst / "node_modules").symlink_to(nm.resolve(), target_is_directory=True)


def _diff(before: str, after: str, name: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile="a/" + name, tofile="b/" + name))


def repair(finding: dict, root: Path, llm, gates: Gates, max_attempts: int = 3,
           workdir: Optional[Path] = None, on_event: Callable[[str, str], None] = lambda k, m: None) -> RepairOutcome:
    """
    Try to fix `finding` (a `Finding.to_dict()`), working on a COPY of `root`. The original tree is never
    modified; a passing patch is returned as a diff for the caller to apply.
    """
    started = time.time()
    root = Path(root).resolve()
    out = RepairOutcome(file=finding["file"])
    if finding["klass"] == "vulnerable-dependency":
        return _repair_dependency(finding, root, gates, out, started, on_event)

    prep = context.prepare(finding, root)
    if prep.unit is None:
        out.status, out.reason = "error", prep.problem
        out.seconds = round(time.time() - started, 2)
        return out

    own_tmp = workdir is None
    work = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="jsrepair_"))
    try:
        tree = work / "tree"
        if tree.exists():
            shutil.rmtree(tree)
        _copy_tree(root, tree)
        target = tree / prep.file
        original = target.read_text(errors="replace")
        feedback = ""
        for n in range(1, max_attempts + 1):
            t0 = time.time()
            att = Attempt(number=n)
            out.attempts.append(att)
            prompt = prep.prompt + (f"\n\nYOUR PREVIOUS ATTEMPT WAS REJECTED:\n{feedback}\nFix this and answer again."
                                    if feedback else "")
            try:
                answer = llm.complete(context.SYSTEM, prompt, purpose=f"js-repair#{n}", max_tokens=2500)
            except Exception as e:                              # a failing model is reported, never swallowed
                att.stage, att.detail = "generation", f"{type(e).__name__}: {str(e)[:200]}"
                out.status, out.reason = "error", f"the model call failed: {att.detail}"
                break
            after, problems = context.apply_answer(tree, prep, answer)
            if after is None:
                att.stage = "policy" if any("[" in p or "outside" in p or "cap" in p or "empties" in p
                                            or "test file" in p for p in problems) else "apply"
                att.detail = feedback = "; ".join(problems)
                att.seconds = round(time.time() - t0, 2)
                on_event("attempt_rejected", f"{n}: {att.stage}: {att.detail[:120]}")
                continue
            target.write_text(after)
            gate_result = _run_gates(tree, finding, gates)
            out.gates = gate_result["gates"]
            att.seconds = round(time.time() - t0, 2)
            if gate_result["failed"]:
                att.stage, att.detail = gate_result["failed"], gate_result["detail"]
                feedback = f"the {att.stage} gate failed: {att.detail}"
                target.write_text(original)                       # next attempt starts from the original
                on_event("attempt_rejected", f"{n}: {att.stage}: {att.detail[:120]}")
                continue
            att.stage = "accepted"
            out.diff = _diff(original, after, prep.file)
            proven = out.gates.get("pov") == PASS and out.gates.get("regression") == PASS
            out.status = "proven" if proven else "patched_unproven"
            out.reason = ("every gate passed" if proven else
                          "no gate failed, but " + ", ".join(k for k, v in out.gates.items() if v != PASS)
                          + " did not pass (skipped gates are never counted as a pass)")
            break
        else:
            last = out.attempts[-1] if out.attempts else Attempt(0)
            out.reason = f"no attempt passed in {max_attempts} tries; last: {last.stage}: {last.detail[:160]}"
        if out.status == "unresolved" and not out.reason:
            out.reason = "no attempt passed"
    finally:
        if own_tmp:
            shutil.rmtree(work, ignore_errors=True)
    out.seconds = round(time.time() - started, 2)
    return out


def _run_gates(tree: Path, finding: dict, gates: Gates) -> dict:
    """Run start, pov and regression on the patched tree. Stops at the first failure."""
    result = {"gates": {}, "failed": "", "detail": ""}
    g = result["gates"]
    g["start"], detail = gates.start(tree)
    if g["start"] == FAIL:
        result.update(failed="start", detail=detail)
        return result
    exploit = finding.get("exploit")
    if exploit:
        g["pov"], detail = gates.replay(tree, exploit)
        if g["pov"] == FAIL:
            result.update(failed="pov", detail=detail)
            return result
    else:
        g["pov"] = SKIPPED                                       # nothing to replay: never a pass
    g["regression"], detail = gates.regress(tree)
    if g["regression"] == FAIL:
        result.update(failed="regression", detail=detail)
    return result


def _repair_dependency(finding: dict, root: Path, gates: Gates, out: RepairOutcome, started: float, on_event) -> RepairOutcome:
    """A dependency fix is deterministic: raise the version to the published fix, then run regression."""
    ev = finding.get("evidence") or {}
    pkg, fix = ev.get("package", ""), ev.get("fix_version", "")
    if not fix:
        out.reason = ("no published fix version for the package itself" +
                      (f"; the vulnerable code is in {ev.get('via_packages')}, which only an update of the "
                       f"parent can change" if ev.get("via_packages") else ""))
        out.seconds = round(time.time() - started, 2)
        return out
    if ev.get("fix_is_major_bump"):
        out.reason = f"the fix is a major version bump ({ev.get('installed')} -> {fix}); needs a human decision"
        out.seconds = round(time.time() - started, 2)
        return out
    before = (root / "package.json").read_text()
    after = patch.bump_dependency(before, pkg, fix)
    if after is None:
        out.status, out.reason = "error", f"{pkg} is not a dependency declared in package.json"
        return out
    problems = patch.check_dependency_patch(before, after)
    if problems:
        out.status, out.reason = "error", "; ".join(problems)
        return out
    work = Path(tempfile.mkdtemp(prefix="jsrepair_dep_"))
    try:
        tree = work / "tree"
        _copy_tree(root, tree)
        (tree / "package.json").write_text(after)
        res = _run_gates(tree, {"exploit": None}, gates)
        out.gates = res["gates"]
        out.attempts.append(Attempt(1, res["failed"] or "accepted", res["detail"]))
        if res["failed"]:
            out.reason = f"the {res['failed']} gate failed after the bump: {res['detail']}"
        else:
            out.diff = _diff(before, after, "package.json")
            out.status = "patched_unproven"
            out.reason = ("version raised; the installed packages were NOT re-resolved, so the gates ran "
                          "against the old node_modules")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out.seconds = round(time.time() - started, 2)
    return out


class RunnerGates:
    """
    A runner called through its CLI: `python -m <module> start|replay|regress ...`. The module comes from the
    constructor or KAVACH_RUNNER_MODULE; there is deliberately no default, so the engine cannot quietly end
    up tied to one application's harness.
    """

    def __init__(self, module: Optional[str] = None, python: str = sys.executable,
                 cwd: Optional[Path] = None, timeout: int = 180):
        module = module or os.getenv("KAVACH_RUNNER_MODULE", "")
        if not module:
            raise ValueError("no runner configured: pass module=... or set KAVACH_RUNNER_MODULE "
                             "to the Python module that implements start/replay/regress")
        self.module, self.python, self.cwd, self.timeout = module, python, cwd, timeout

    def _run(self, *args) -> tuple[int, str]:
        try:
            p = subprocess.run([self.python, "-m", self.module, *args], capture_output=True, text=True,
                               timeout=self.timeout, cwd=self.cwd)
        except subprocess.TimeoutExpired:
            return 124, f"timed out after {self.timeout}s"
        return p.returncode, (p.stdout or p.stderr)[-400:]

    def start(self, tree: Path) -> tuple[str, str]:
        code, text = self._run("start", "--tree", str(tree))
        return (PASS if code == 0 else FAIL), text

    def replay(self, tree: Path, exploit: dict) -> tuple[str, str]:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(exploit, fh)
        try:
            code, text = self._run("replay", "--tree", str(tree), "--exploit", fh.name)
        finally:
            Path(fh.name).unlink(missing_ok=True)
        if code == 0:
            return PASS, "no longer exploitable"
        return (FAIL, "still exploitable: " + text) if code == 1 else (FAIL, "replay error: " + text)

    def regress(self, tree: Path) -> tuple[str, str]:
        code, text = self._run("regress", "--tree", str(tree))
        return (PASS if code == 0 else FAIL), text
