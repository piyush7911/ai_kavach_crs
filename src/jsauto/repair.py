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
import re
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
    stage: str = ""                 # generation | apply | policy | start | pov | regression | hardening | repeat | accepted
    detail: str = ""
    seconds: float = 0.0
    agent: str = ""                 # alpha | beta | gamma
    model: str = ""                 # set only when a stronger model than the default was used


@dataclass
class RepairOutcome:
    status: str = "unresolved"      # proven | patched_unproven | advisory | unresolved | error
    reason: str = ""
    attempts: list = field(default_factory=list)
    gates: dict = field(default_factory=dict)
    diff: str = ""
    file: str = ""
    seconds: float = 0.0
    hardened: bool = False          # every exploit variant was replayed against the patch and none worked
    new_text: str = ""              # the patched file's full text, for the caller to apply

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
           workdir: Optional[Path] = None, on_event: Callable[[str, str], None] = lambda k, m: None,
           variants: Optional[list] = None, strategy: str = "single") -> RepairOutcome:
    """
    Try to fix `finding` (a `Finding.to_dict()`), working on a COPY of `root`. The original tree is never
    modified; a passing patch is returned as a diff for the caller to apply.

    `variants` are other spellings of the exploit (probes.variants_for). After the primary exploit is
    blocked and regression passes, every variant is replayed: a patch that blocks one spelling and
    leaks another is overfitted, and is rejected with the leaking variant as feedback, inside the loop.

    `strategy` "single": alpha only, `max_attempts` tries. "adaptive": `max_attempts` tries PER TIER, in
    order alpha (analyst), beta (minimal change), gamma (standard remediation, on a stronger model when one
    is declared and usable). A later tier is told what the earlier ones tried and how each was rejected.
    An easy bug costs one call; a hard one is handed on. An identical answer to an earlier one skips the
    rest of that tier: at temperature 0 asking again would only repeat the same rejection.
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
        seen_answers: dict[str, int] = {}
        history: list[tuple] = []                                 # (agent, stage, detail) of every rejection
        skipped: set[str] = set()
        schedule = _schedule(strategy, max_attempts)
        strong: Optional[str] = None
        strong_resolved = False
        repeat_note = ""
        accepted = False
        for n, (agent, wants_strong) in enumerate(schedule, 1):
            if agent in skipped:
                continue
            t0 = time.time()
            att = Attempt(number=n, agent=agent)
            out.attempts.append(att)
            if wants_strong and not strong_resolved:
                probe = getattr(llm, "usable_escalate_model", None)
                strong, strong_resolved = ((probe() if callable(probe) else "") or None), True
            kw = {"model": strong} if (wants_strong and strong) else {}
            att.model = kw.get("model", "")
            prompt = prep.prompt + _handoff(history, feedback)
            try:
                answer = llm.complete(context.system_for(agent), prompt, purpose=f"js-repair#{n}",
                                      max_tokens=2500, **kw)
            except Exception as e:                              # a failing model is reported, never swallowed
                att.stage, att.detail = "generation", f"{type(e).__name__}: {str(e)[:200]}"
                out.status, out.reason = "error", f"the model call failed: {att.detail}"
                break
            key = re.sub(r"\s+", " ", patch.extract_code(answer)).strip()
            if key in seen_answers:
                att.stage = "repeat"
                att.detail = f"the model returned the same answer as attempt {seen_answers[key]}"
                att.seconds = round(time.time() - t0, 2)
                skipped.add(agent)
                repeat_note = f"; stopped asking {agent} after a repeat ({att.detail})"
                on_event("attempt_rejected", f"{n}: {agent}: repeat: {att.detail}")
                continue
            seen_answers[key] = n
            after, problems = context.apply_answer(tree, prep, answer)
            if after is None:
                att.stage = "policy" if any("[" in p or "outside" in p or "cap" in p or "empties" in p
                                            or "test file" in p for p in problems) else "apply"
                att.detail = feedback = "; ".join(problems)
                att.seconds = round(time.time() - t0, 2)
                history.append((agent, att.stage, att.detail[:200]))
                on_event("attempt_rejected", f"{n}: {agent}: {att.stage}: {att.detail[:120]}")
                continue
            target.write_text(after)
            gate_result = _run_gates(tree, finding, gates, variants)
            out.gates = gate_result["gates"]
            att.seconds = round(time.time() - t0, 2)
            if gate_result["failed"]:
                att.stage, att.detail = gate_result["failed"], gate_result["detail"]
                feedback = f"the {att.stage} gate failed: {att.detail}"
                history.append((agent, att.stage, att.detail[:200]))
                target.write_text(original)                       # next attempt starts from the original
                on_event("attempt_rejected", f"{n}: {agent}: {att.stage}: {att.detail[:120]}")
                continue
            att.stage = "accepted"
            accepted = True
            out.new_text = after
            out.diff = _diff(original, after, prep.file)
            proven = out.gates.get("pov") == PASS and out.gates.get("regression") == PASS
            out.hardened = out.gates.get("hardening") == PASS
            out.status = "proven" if proven else "patched_unproven"
            out.reason = (("every gate passed" + ("" if out.hardened else "; no exploit variants were replayed")) if proven else
                          "no gate failed, but " + ", ".join(k for k, v in out.gates.items() if v != PASS)
                          + " did not pass (skipped gates are never counted as a pass)")
            break
        if not accepted and out.status != "error":
            last = next((a for a in reversed(out.attempts) if a.stage != "repeat"), Attempt(0))
            out.reason = (f"no attempt passed in {len(out.attempts)} tries; last: {last.stage}: {last.detail[:160]}"
                          + repeat_note)
    finally:
        if own_tmp:
            shutil.rmtree(work, ignore_errors=True)
    out.seconds = round(time.time() - started, 2)
    return out


def _schedule(strategy: str, per_tier: int) -> list[tuple[str, bool]]:
    """(agent, uses the stronger model) for each attempt, in order."""
    if strategy == "adaptive":
        return [("alpha", False)] * per_tier + [("beta", False)] * per_tier + [("gamma", True)] * per_tier
    return [("alpha", False)] * per_tier


def _handoff(history: list, feedback: str) -> str:
    """What was already tried and why it was rejected, so the next attempt does not repeat it."""
    if not history:
        return ""
    lines = [f"- ({a}) {stage}: {detail}" for a, stage, detail in history[:-1][-6:]]
    out = ["", "", f"YOUR PREVIOUS ATTEMPT WAS REJECTED:\n{feedback}\nFix this and answer again."]
    if lines:
        out += ["", "EARLIER ATTEMPTS (all rejected; do not repeat them):"] + lines
    return "\n".join(out)


def _run_gates(tree: Path, finding: dict, gates: Gates, variants: Optional[list] = None) -> dict:
    """Run start, pov, regression and hardening on the patched tree. Stops at the first failure."""
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
    # Hardening: the primary exploit is blocked and behaviour is intact; now try other spellings of it.
    if exploit and variants and g["pov"] == PASS:
        for i, v in enumerate(variants, 1):
            state, vdetail = gates.replay(tree, v)
            if state == FAIL:
                g["hardening"] = FAIL
                result.update(failed="hardening", detail=(
                    f"the primary exploit is blocked but variant {i} of {len(variants)} still works "
                    f"({v.get('method', 'GET')} {v.get('path', '')[:100]}): {vdetail}. Block the attack, "
                    "not one spelling of it"))
                return result
        g["hardening"] = PASS
    else:
        g["hardening"] = SKIPPED
    return result


def _repair_dependency(finding: dict, root: Path, gates: Gates, out: RepairOutcome, started: float, on_event) -> RepairOutcome:
    """A dependency fix is a RECOMMENDATION, not an action. The final evaluation is air-gapped: with no
    network the package tree cannot be re-resolved/reinstalled, and an un-reinstalled bump proves nothing.
    So we report the exact version to upgrade to (as a suggested diff for display) but deliberately do NOT
    edit the manifest, do NOT run gates, and hand back no auto-apply payload. The operator applies the
    advice where there is network. Status is `advisory`."""
    ev = finding.get("evidence") or {}
    pkg, fix = ev.get("package", ""), ev.get("fix_version", "")
    if not fix:                                              # nothing to recommend -> stays unresolved
        out.reason = ("no published fix version for the package itself" +
                      (f"; the vulnerable code is in {ev.get('via_packages')}, which only an update of the "
                       f"parent can change" if ev.get("via_packages") else ""))
        out.seconds = round(time.time() - started, 2)
        return out
    out.status = "advisory"
    if ev.get("fix_is_major_bump"):
        out.reason = (f"recommend (needs a human decision): major version bump {ev.get('installed')} -> "
                      f"{fix} for {pkg}; not applied (air-gapped, and a major bump can break the app)")
        out.seconds = round(time.time() - started, 2)
        return out
    before = (root / "package.json").read_text()
    after = patch.bump_dependency(before, pkg, fix)
    if after is None:
        out.status, out.reason = "error", f"{pkg} is not a dependency declared in package.json"
        out.seconds = round(time.time() - started, 2)
        return out
    out.diff = _diff(before, after, "package.json")          # the SUGGESTED change, for display only
    out.reason = (f"recommend upgrading {pkg} to {fix}; NOT applied — the air-gapped evaluation cannot "
                  "re-resolve/reinstall/test dependencies offline, so this stays advisory")
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

    def exploitable(self, tree: Path, exploit: dict) -> tuple[Optional[bool], str]:
        """True/False if the exploit works against `tree`; None if the runner could not tell (an error)."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(exploit, fh)
        try:
            code, text = self._run("replay", "--tree", str(tree), "--exploit", fh.name)
        finally:
            Path(fh.name).unlink(missing_ok=True)
        return {0: False, 1: True}.get(code), text

    def replay(self, tree: Path, exploit: dict) -> tuple[str, str]:
        """Gate view: PASS means the exploit no longer works. An error is a FAIL, never a pass."""
        works, text = self.exploitable(tree, exploit)
        if works is False:
            return PASS, "no longer exploitable"
        return (FAIL, "still exploitable: " + text) if works else (FAIL, "replay error: " + text)

    def regress(self, tree: Path) -> tuple[str, str]:
        code, text = self._run("regress", "--tree", str(tree))
        return (PASS if code == 0 else FAIL), text
