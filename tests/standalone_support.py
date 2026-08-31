"""
Shared support for the STANDALONE evaluation suites
(`tests/vanguard_nightmare/`, `tests/public_benchmarks_extension/`).

These suites deliberately run outside `benchmark.py` so they can be evaluated
independently. That independence previously cost them the two safeguards the
main harness has, and both absences produced false results:

  1. **No pre-flight.** The runners printed "Executing pre-flight PoV
     verification..." and never performed one. A PoV that passes on the
     *unpatched* original proves nothing, but was still counted as proof.

  2. **Hardening defaulted to SURVIVED.** If the winning patch could not be
     re-applied to the temporary copy, the runner reported `SURVIVED` — a patch
     that was never hardened at all. It also inspected only `diverged`,
     discarding the adversarial re-fuzzing verdict entirely.

This module provides both correctly, so the standalone suites reach the same
evidentiary bar as the main harness without being merged into it.
"""

import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.patch_validator.drv_loop import DRVLoop
from src.patch_validator.hardening import HardeningVerdict


@dataclass
class PreflightVerdict:
    """Whether a target's contract is sound BEFORE any agent touches it."""

    builds: bool = False
    build_error: str = ""
    pov_configured: bool = False
    pov_reproduces: bool = False
    regression_baseline_ok: bool = False
    detail: str = ""

    @property
    def pov_usable(self) -> bool:
        """A PoV may gate a result only if it demonstrably detects the real bug."""
        return self.builds and self.pov_configured and self.pov_reproduces

    def summary(self) -> str:
        if not self.builds:
            return f"EXCLUDED — original does not build: {self.build_error[:160]}"
        if not self.pov_configured:
            return "no PoV configured (patch cannot be dynamically proven)"
        if not self.pov_reproduces:
            return (
                "PoV DOES NOT REPRODUCE on the unpatched original — gate disabled, "
                "this target cannot be counted as PoV-proven"
            )
        return "PoV reproduces on the original; gate is valid"


def preflight(target) -> PreflightVerdict:
    """
    Compile the target UNPATCHED and check its verification contract.

    Returns a verdict rather than raising: a broken contract should be reported
    and excluded, not silently treated as success.
    """
    verdict = PreflightVerdict(pov_configured=target.pov_command is not None)

    with tempfile.TemporaryDirectory(prefix="standalone_pre_") as tmp:
        workspace = Path(tmp)
        try:
            src = DRVLoop._materialise(workspace, target.file_path, target.source_dir)
        except FileNotFoundError as e:
            verdict.build_error = str(e)
            return verdict

        binary = workspace / "kavach_target"
        ctx = {
            "src": str(src), "srcdir": str(src.parent),
            "bin": str(binary), "workspace": str(workspace),
        }

        ok, detail = DRVLoop._run(DRVLoop.expand(target.build_command, ctx), "Build", cwd=workspace)
        verdict.builds = ok
        if not ok:
            verdict.build_error = detail
            return verdict

        if target.pov_command:
            # A PoV command exits 0 when the vulnerability is ABSENT. On the
            # unpatched original it must therefore FAIL.
            ok, detail = DRVLoop._run(DRVLoop.expand(target.pov_command, ctx), "PoV", cwd=workspace)
            verdict.pov_reproduces = not ok
            verdict.detail = detail[:400]

        if target.regression_command:
            ok, _ = DRVLoop._run(
                DRVLoop.expand(target.regression_command, ctx), "Regression", cwd=workspace
            )
            verdict.regression_baseline_ok = ok

    return verdict


def harden_result(target, result, hardener, extractor) -> HardeningVerdict:
    """
    Re-apply the winning patch to a clean copy and try to falsify it.

    Correctness requirements this enforces, each of which was previously wrong:

      * A patch that cannot be re-applied yields `skipped_reason`, **never**
        a survival verdict.
      * Both falsification channels are honoured — `overfitted` (adversarial
        re-fuzzing) as well as `diverged` (differential testing).
      * Whole-function replacements are handled, not just unified diffs. The
        old code required `patch_res.analysis and patch_res.patch_diff`, which
        excluded Beta/Gamma (no analysis) and every replacement patch (no diff).
    """
    verdict = HardeningVerdict()

    report = result.agent_reports.get(result.winning_agent) if result.winning_agent else None
    winning = report.winning_iteration if report else None
    if not winning:
        verdict.skipped_reason = "no winning iteration recorded"
        return verdict

    with tempfile.TemporaryDirectory(prefix="standalone_harden_") as tmp:
        work = Path(tmp)
        try:
            patched = DRVLoop._materialise(work, target.file_path, target.source_dir)
        except FileNotFoundError as e:
            verdict.skipped_reason = str(e)
            return verdict

        applied = False
        if winning.replacement and extractor:
            name, source = winning.replacement
            applied = extractor.replace_function(str(patched), name, source)
        if not applied and winning.patch_diff:
            applied, _ = DRVLoop._apply_patch(work, patched, winning.patch_diff)

        if not applied:
            verdict.skipped_reason = (
                "could not re-apply the winning patch — hardening did NOT run, "
                "so this patch is unhardened rather than survived"
            )
            return verdict

        return hardener.harden(
            target_id=target.id,
            original_source=Path(target.file_path),
            patched_source=patched,
            build_command=target.build_command,
            behaviour_contract=getattr(target, "behaviour_contract", "preserve"),
            evasion_command=getattr(target, "evasion_command", None),
        )


def hardening_label(verdict: HardeningVerdict) -> str:
    """
    Human-readable status that never overstates what happened.

    Distinguishes "we tried to break it and could not" from "we never tried" —
    the conflation of those two was the original defect.
    """
    if verdict.skipped_reason:
        return "NOT HARDENED"
    if verdict.overfitted:
        return "FALSIFIED (overfitted)"
    if verdict.evaded:
        return "FALSIFIED (validation bypassed)"
    if verdict.diverged:
        return "FALSIFIED (behaviour changed)"
    # SURVIVED requires that at least one falsification attempt actually
    # produced a result. The evasion battery counts: for an input-validation fix
    # it is the only applicable check, since re-fuzzing has no crash to find and
    # differential testing cannot judge a deliberately narrowed input domain.
    #
    # `has_evidence` also requires differential testing to have compared at
    # least one input. The differ skips inputs on which the ORIGINAL crashes, so
    # a target whose only code path is the vulnerable one yields
    # "differential(0 inputs): behaviour preserved" — which is not evidence.
    return "SURVIVED" if verdict.has_evidence else "NOT HARDENED"
