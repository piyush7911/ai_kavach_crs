"""
Repair stage: patch a fuzzer-found bug in an uploaded repository, verify the
patch with the same gates the benchmark uses, then try to break it.

What differs from the benchmark flow, and why
---------------------------------------------
* The proof of vulnerability is the fuzzer's own crashing input, replayed on a
  rebuild of the PATCHED repository. Nothing about the bug is declared in advance.
* There is no test command in an uploaded repo, so the regression gate is the
  behaviour oracle the campaign recorded (`replay_check.sh`): the patched build
  must reproduce the original's return values and output on every corpus input
  the original handled cleanly. If no such inputs exist the regression gate is
  reported SKIPPED, never passed.
* Hardening is done here because the benchmark's hardening assumes a single
  source file and argv-style inputs. Here the binary is a libFuzzer harness, so
  the attacks are: re-fuzz the patched build (an overfitted patch only stops one
  input), and differential-test it against the original on the corpus plus
  mutated variants of the crashing input (a gutted patch stops everything).

Outcomes are never rounded up. `proven` needs a clean PoV gate AND a hardening
check that genuinely compared something; a patch that passed the gates but could
not be attacked is `patched_unhardened`.
"""

import dataclasses
import difflib
import re
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.autonomy import build, campaign
from src.events import EventSink, NULL_SINK
from src.patch_validator.drv_loop import DRVLoop
from src.patch_validator.hardening import HardeningVerdict

POV_RUNNER = (Path(__file__).resolve().parent.parent.parent
              / "tests" / "benchmarks" / "harness" / "pov_run.sh")


@dataclass
class RepairOutcome:
    status: str                       # proven | patched_unhardened | falsified | unresolved
    reason: str = ""
    winning_agent: str = ""
    iterations: int = 0
    gates: dict = field(default_factory=dict)
    hardening: dict = field(default_factory=dict)
    patch_text: str = ""              # what the agent returned (diff or whole function)
    diff: str = ""                    # unified diff, original file -> patched file
    cost_usd: float = 0.0
    seconds: float = 0.0
    agents: list = field(default_factory=list)
    previous_attempts: list = field(default_factory=list)   # falsified patches tried before this one

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        return d


def variants_of(data: bytes) -> list[bytes]:
    """
    Neighbours of a crashing input, to test whether a patch fixed the BUG or only
    the one input. Deterministic, small, and chosen to straddle the boundary
    conditions that off-by-one and length bugs depend on.
    """
    n = len(data)
    out: list[bytes] = []
    if n > 1:
        out += [data[:1], data[: max(1, n // 2)], data[:-1]]
    out += [data + b"A", data + bytes(range(16)), data * 2]
    for i in range(min(n, 8)):                       # flip the first few bytes
        b = bytearray(data)
        b[i] ^= 0xFF
        out.append(bytes(b))
    seen, uniq = set(), []
    for v in out:
        if v not in seen and v != data:
            seen.add(v)
            uniq.append(v)
    return uniq


def _last_stage(rep) -> str:
    """The gate that rejected the agent's final attempt."""
    return rep.iterations[-1].failure_stage if rep.iterations else ""


def gate_commands(script: Path, snap_name: str, crash_input: Path, replay_check: Optional[Path],
                  golden: Optional[Path], crash_inputs: Optional[list] = None
                  ) -> tuple[str, str, Optional[str]]:
    """
    The three gate commands. `{workspace}` and `{bin}` are filled in by the DRV loop.

    The PoV gate replays EVERY input triage grouped under this root cause, not just
    the first. A patch that fixes one input and not its siblings otherwise clears the
    gate and is only caught later by hardening, which costs a whole extra round.
    """
    q = shlex.quote
    build_cmd = f'sh {q(str(script))} "{{workspace}}/{snap_name}" "{{bin}}"'
    inputs = [Path(p).resolve() for p in (crash_inputs or [crash_input])]
    if crash_input.resolve() not in inputs:
        inputs.insert(0, crash_input.resolve())
    inputs = [p for p in dict.fromkeys(inputs) if p.exists()][:8]
    pov_cmd = "; ".join(f'sh {q(str(POV_RUNNER))} "{{bin}}" {q(str(p))} || exit 1' for p in inputs)
    test_cmd = (f'sh {q(str(replay_check))} "{{bin}}" {q(str(golden))}'
                if replay_check and golden and golden.exists() and golden.stat().st_size else None)
    return build_cmd, pov_cmd, test_cmd


def _reapply_winning_patch(result, vuln, snap_root: Path, workdir: Path, extractor):
    """Re-apply the winning patch to a clean copy of the snapshot. Returns (patched_src, root)."""
    report = result.agent_reports.get(result.winning_agent)
    winning = report.winning_iteration if report else None
    if not winning:
        raise RuntimeError("no winning iteration was recorded")
    tmp = Path(tempfile.mkdtemp(prefix="patched_", dir=workdir))
    patched_src = DRVLoop._materialise(tmp, vuln.file_path, str(snap_root))
    applied = False
    if winning.replacement and extractor:
        name, source = winning.replacement
        applied = extractor.replace_function(str(patched_src), name, source)
    if not applied and winning.patch_diff:
        applied, _ = DRVLoop._apply_patch(tmp, patched_src, winning.patch_diff)
    if not applied:
        raise RuntimeError("the winning patch could not be re-applied to a clean copy")
    return patched_src, tmp / snap_root.name, winning


def _describe_crash(output: str, crash: Path) -> dict:
    """Class and location of a sanitizer crash, from its report."""
    kind = re.search(r"ERROR: (\w+Sanitizer): ([\w\- ]+?) on", output)
    frame = re.search(r"#\d+ 0x[0-9a-f]+ in (\w+) (\S+?):(\d+)", output)
    return {"input": crash.name,
            "class": kind.group(2).strip() if kind else crash.name.split("-")[0],
            "where": f"{frame.group(1)} {Path(frame.group(2)).name}:{frame.group(3)}" if frame else ""}


def harden(*, script: Path, original_bin: Path, patched_root: Path, work: Path, seed_dir: Path,
           corpus_dir: Path, crash_input: Path, refuzz_seconds: int) -> HardeningVerdict:
    """Try to falsify a patch that already cleared every gate."""
    v = HardeningVerdict()
    started = time.time()
    ws = work / "harden"
    ws.mkdir(parents=True, exist_ok=True)

    patched = build.build(script, patched_root, ws / "bin" / "patched", ws)
    if not patched.ok:
        v.skipped_reason = "the patched tree did not build for hardening: " + patched.error[:160]
        return v

    # 1. Re-fuzz the patched build. A patch that only silenced one input still
    #    crashes elsewhere; seed with the original crash and the corpus.
    hseeds = ws / "seeds"
    hseeds.mkdir(exist_ok=True)
    for src in [crash_input, *sorted(seed_dir.glob("*")), *sorted(corpus_dir.glob("*"))][:120]:
        if src.is_file():
            shutil.copy(src, hseeds / src.name)
    fz = campaign.fuzz(patched.binary, ws, refuzz_seconds, hseeds, corpus=ws / "corpus",
                       ignore_crashes=True)
    if fz.ran:
        v.overfitting_checked = True
        # A crash the ORIGINAL also has is a separate, pre-existing bug, not the patch's
        # fault: blaming the patch would hide a real finding. Only a crash on an input
        # where the original is clean was introduced (or left unfixed) by the patch.
        introduced = []
        for crash in fz.crashes[:30]:
            r = campaign.replay(original_bin, crash, ws, trace=False, timeout=20)
            if r.ran and (r.ok and not r.timed_out):
                introduced.append(crash)
            else:
                v.additional_bugs.append(_describe_crash(r.output, crash))
        if introduced:
            v.overfitted = True
            v.new_crash_input = str(introduced[0])
            kind = introduced[0].name.split("-")[0]
            what = {"oom": "memory exhaustion across calls (typically a leak the patch introduced; "
                           "it accumulates, so one input alone may not reproduce it)",
                    "timeout": "a hang"}.get(kind, "a sanitizer crash")
            v.new_crash_detail = (f"re-fuzzing the patched build found {what} on an input the "
                                  f"original handles cleanly ({introduced[0].name})")
    else:
        v.skipped_reason = f"re-fuzzing could not run: {fz.note}"

    if v.overfitted:
        # Already falsified. The differential check would only add seconds to a verdict
        # that cannot change, so it is skipped and reported as not run.
        v.differential_note = "not run: the re-fuzz had already falsified the patch"
        v.seconds = round(time.time() - started, 2)
        return v

    # 2. Differential test against the original: the corpus, the seeds and mutated
    #    neighbours of the crashing input. Where the original is clean, the
    #    patched build must behave identically.
    vdir = ws / "variants"
    vdir.mkdir(exist_ok=True)
    inputs = [p for p in [*seed_dir.glob("*"), *corpus_dir.glob("*")] if p.is_file()]
    for i, data in enumerate(variants_of(crash_input.read_bytes())):
        p = vdir / f"v{i:02d}"
        p.write_bytes(data)
        inputs.append(p)
    compared, diffs = campaign.compare_behaviour(original_bin, patched.binary, inputs, ws)
    v.differential_checked = True
    v.inputs_tested = compared
    if diffs:
        v.diverged = True
        v.divergence_detail = "; ".join(diffs[:3])
    v.differential_note = f"compared on {compared} input(s) where the original is clean"
    v.seconds = round(time.time() - started, 2)
    return v


_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)")
_REGION = re.compile(r"located (\d+) bytes? (after|to the right of|to the left of|before|inside)"
                     r"[^\n]*?(\d+)-byte region")


def explain_crash(vuln, crash_input: Path) -> str:
    """
    A plain brief of the failure, derived only from the crash itself: the faulting
    line in context, the kind of access and how far outside the buffer it landed,
    the input that triggers it, and the constraints a good fix must respect. The
    raw sanitizer report is already in the prompt; models fix what they can state.
    """
    parts = ["", "ROOT-CAUSE BRIEF (derived from the crash, not guessed):"]
    report = vuln.crash_trace or ""
    acc, reg = _ACCESS.search(report), _REGION.search(report)
    if acc:
        parts.append(f"- The faulting access is a {acc.group(1)} of {acc.group(2)} byte(s).")
    if reg:
        where = {"after": "past the end of", "to the right of": "past the end of",
                 "to the left of": "before the start of", "before": "before the start of",
                 "inside": "inside"}[reg.group(2)]
        parts.append(f"- It lands {reg.group(1)} byte(s) {where} a {reg.group(3)}-byte allocation. "
                     "That allocation is sized exactly by the caller, so nothing beyond it is readable.")
    try:
        lines = Path(vuln.file_path).read_text(errors="replace").splitlines()
        lo, hi = max(0, vuln.line_number - 4), min(len(lines), vuln.line_number + 3)
        parts.append(f"- Faulting statement, {Path(vuln.file_path).name}:{vuln.line_number} (>> marks it):")
        parts += [("  >> " if i + 1 == vuln.line_number else "     ") + lines[i] for i in range(lo, hi)]
    except OSError:
        pass
    try:
        data = crash_input.read_bytes()[:64]
        parts.append(f"- A triggering input ({crash_input.stat().st_size} bytes, first {len(data)} shown): {data!r}")
    except OSError:
        pass
    parts += [
        "- Find the exact condition under which the code reads or writes beyond the end of its data, "
        "and make THAT condition safe (for example a pointer that is advanced past a terminator "
        "without re-checking it). A check that compares quantities which can never differ in the "
        "failing way does not fix anything.",
        "- Change only the faulting function. Do not delete or rewrite comments, reformat, or alter "
        "behaviour for inputs that already work; the smallest correct change wins.",
    ]
    return "\n".join(parts)


def expand_pov_inputs(original_bin: Path, crash_inputs: list, work: Path, vuln) -> list:
    """
    Crash inputs plus near-variants on which the ORIGINAL crashes at the SAME line.
    A real fix must stop all of them; a patch that only silences the single recorded
    input is rejected inside the repair loop, with the failing input as feedback,
    instead of costing a hardening round and a retry. A variant that crashes the
    original somewhere else is not this bug's business and is left out.
    """
    from src.analysis_engine.crash_triage import CrashTriage

    vdir = work / "pov_variants"
    vdir.mkdir(parents=True, exist_ok=True)
    out = [Path(p) for p in crash_inputs]
    seen = {p.read_bytes() for p in out if p.exists()}
    for base in list(out)[:2]:
        if not base.exists():
            continue
        for i, data in enumerate(variants_of(base.read_bytes())):
            if data in seen:
                continue
            p = vdir / f"{base.name[:14]}-v{i:02d}"
            p.write_bytes(data)
            r = campaign.replay(original_bin, p, work, trace=False, timeout=15)
            if not r.ran or r.timed_out or r.ok:
                continue
            sig = CrashTriage.parse_sanitizer_report(r.output, Path(vuln.file_path).parents[0])
            if sig is not None and sig.line_number == vuln.line_number and \
                    Path(sig.file_path).name == Path(vuln.file_path).name:
                seen.add(data)
                out.append(p)
    return out[:12]


HARDENING_RETRIES = 1


def repair(*, hardening_retries: int = HARDENING_RETRIES, **kw) -> RepairOutcome:
    """
    Patch, verify and attack one bug. A patch that clears every gate but is
    falsified by hardening (typically one that deleted a cleanup call) goes back
    to the model once with the real reason. The first failure is kept in
    `previous_attempts`, so a retry is never presented as a first-try success.
    """
    vuln = kw.pop("vuln")
    vuln = dataclasses.replace(vuln, description=vuln.description + explain_crash(vuln, kw["crash_input"]))
    kw["crash_inputs"] = expand_pov_inputs(kw["original_bin"], kw.get("crash_inputs") or [kw["crash_input"]],
                                           kw["work"], vuln)
    history: list[dict] = []
    outcome = _repair_once(vuln=vuln, **kw)
    while outcome.status == "falsified" and len(history) < hardening_retries:
        reason = outcome.hardening.get("detail") or outcome.reason
        history.append({"status": outcome.status, "reason": reason, "diff": outcome.diff})
        kw.get("events", NULL_SINK).emit("hardening_retry", stage="repair", status="info",
                                         message=f"{vuln.id}: retry {len(history)}", reason=reason[:300])
        vuln = dataclasses.replace(vuln, description=(
            vuln.description + "\n\nA previous patch passed the build, the proof-of-vulnerability "
            "and the behaviour check but was REJECTED by a stricter check: " + reason +
            " Fix the bug without removing cleanup or changing behaviour on other paths; "
            "change as little as possible."))
        retry = _repair_once(vuln=vuln, **kw)
        retry.cost_usd += outcome.cost_usd
        retry.seconds += outcome.seconds
        outcome = retry
    outcome.previous_attempts = history
    return outcome


def _repair_once(*, orchestrator, extractor, vuln, snap_root: Path, script: Path, original_bin: Path,
                 crash_input: Path, replay_check: Optional[Path], golden: Optional[Path], work: Path,
                 seed_dir: Path, corpus_dir: Path, refuzz_seconds: int = 20,
                 events: EventSink = NULL_SINK, agents: Optional[list[str]] = None,
                 crash_inputs: Optional[list] = None) -> RepairOutcome:
    """One patch-and-harden attempt."""
    started = time.time()
    snap_root = Path(snap_root).resolve()
    build_cmd, pov_cmd, test_cmd = gate_commands(script, snap_root.name, crash_input, replay_check,
                                                 golden, crash_inputs)

    events.emit("stage_start", stage="repair", status="info", message=f"{vuln.id}: agents patching")
    result = orchestrator.process_vulnerability(
        vuln, build_command=build_cmd, pov_command=pov_cmd, test_command=test_cmd,
        agents=agents, source_dir=str(snap_root))

    agents_summary = []
    for name, rep in result.agent_reports.items():
        if rep is None:
            agents_summary.append({"agent": name, "success": False, "error": "agent raised"})
        else:
            agents_summary.append({"agent": name, "success": rep.success, "iterations": rep.total_iterations,
                                   "last_failure_stage": _last_stage(rep)})

    out = RepairOutcome(status="unresolved", cost_usd=result.total_cost_usd, agents=agents_summary,
                        seconds=round(time.time() - started, 2))
    if result.status != "patched":
        stages = sorted({a.get("last_failure_stage") for a in agents_summary if a.get("last_failure_stage")})
        out.reason = ("no agent produced a patch that cleared every gate"
                      + (f" (last failing gate: {', '.join(stages)})" if stages else ""))
        events.emit("stage_done", stage="repair", status="fail", message=out.reason)
        return out

    report = result.agent_reports[result.winning_agent]
    win = report.winning_iteration
    out.winning_agent = result.winning_agent
    out.iterations = report.total_iterations
    out.patch_text = result.winning_patch or ""
    out.gates = {"policy": win.policy_ok, "build": win.syntax_ok, "pov": win.pov_ok,
                 "regression": win.regression_ok, "post_scan": win.post_scan_ok}
    events.emit("stage_done", stage="repair", status="ok",
                message=f"{vuln.id}: patched by {out.winning_agent} in {report.total_iterations} iteration(s)")

    # Attack the patch.
    events.emit("stage_start", stage="harden", status="info", message="re-fuzz + differential")
    try:
        patched_src, patched_root, _ = _reapply_winning_patch(result, vuln, snap_root, work, extractor)
        original_text = Path(vuln.file_path).read_text(errors="replace").splitlines(keepends=True)
        out.diff = "".join(difflib.unified_diff(
            original_text, patched_src.read_text(errors="replace").splitlines(keepends=True),
            fromfile="a/" + Path(vuln.file_path).name, tofile="b/" + Path(vuln.file_path).name))
        verdict = harden(script=script, original_bin=original_bin, patched_root=patched_root, work=work,
                         seed_dir=seed_dir, corpus_dir=corpus_dir, crash_input=crash_input,
                         refuzz_seconds=refuzz_seconds)
    except Exception as e:
        verdict = HardeningVerdict(skipped_reason=f"hardening could not run: {type(e).__name__}: {e}")

    out.hardening = {
        "summary": verdict.summary(), "refuzzed": verdict.overfitting_checked, "overfitted": verdict.overfitted,
        "differential_checked": verdict.differential_checked, "inputs_compared": verdict.inputs_tested,
        "diverged": verdict.diverged, "skipped_reason": verdict.skipped_reason,
        "survived": verdict.survived, "falsified": verdict.falsified,
        "detail": verdict.new_crash_detail or verdict.divergence_detail,
        "additional_bugs": verdict.additional_bugs,
    }
    if verdict.falsified:
        out.status = "falsified"
        out.reason = "the patch cleared every gate but hardening broke it: " + verdict.summary()
    elif verdict.survived:
        out.status = "proven"
        out.reason = "every gate passed and hardening could not falsify the patch"
        if verdict.additional_bugs:
            where = sorted({b["where"] or b["class"] for b in verdict.additional_bugs})
            out.reason += (f"; re-fuzzing also found {len(where)} separate pre-existing bug(s) the "
                           f"original has too (not caused by the patch): {', '.join(where)[:160]}")
    else:
        out.status = "patched_unhardened"
        out.reason = ("every gate passed, but no hardening check produced evidence: "
                      + (verdict.skipped_reason or verdict.summary()))
    if out.gates.get("regression") != "pass":
        out.reason += " (regression gate: " + str(out.gates.get("regression")) + ")"
    out.seconds = round(time.time() - started, 2)
    events.emit("stage_done", stage="harden", status="ok" if out.status == "proven" else "fail",
                message=f"{vuln.id}: {out.status}")
    return out
