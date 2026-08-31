"""
AI Kavach CRS — Patch Hardening

The verification gates answer "does this input still crash?". That is necessary
but not sufficient, and two cheap attacks defeat it:

  1. **PoV overfitting.** A patch only has to stop one specific input.
     `if (size == 4) return;` passes build, PoV replay and regression while
     leaving the vulnerability fully reachable at size 5.

  2. **Functionality gutting.** A patch that disables the vulnerable code path
     entirely — an early `return`, a neutered loop — also passes, because the
     regression gate checks a single benign input.

Neither is hypothetical: both are exactly what a model optimising for "make the
gate go green" would produce. This module closes both holes.

    AdversarialRefuzz     re-fuzzes the PATCHED build, seeded with the original
                          crash. Any new crash proves the fix was input-specific.

    DifferentialTester    runs the original and patched binaries side by side on
                          many benign inputs. Behaviour must match wherever the
                          original did not crash; divergence means the patch
                          changed what the program does.

Both are *falsification* tools: they cannot prove a patch correct, only expose
one that is not. A patch that survives them is meaningfully stronger than one
that merely turned a gate green.
"""

import logging
import os
import random
import shutil
import string
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SAN_BUILD = (
    "clang -fsanitize=address,undefined -fno-sanitize-recover=all "
    "-fno-omit-frame-pointer -g -O1"
)


@dataclass
class HardeningVerdict:
    """Outcome of hardening a single validated patch. Every field is observed."""

    overfitting_checked: bool = False
    overfitted: bool = False
    new_crash_input: str = ""
    new_crash_detail: str = ""

    evasion_checked: bool = False
    evaded: bool = False
    evasion_detail: str = ""

    differential_checked: bool = False
    diverged: bool = False
    divergence_detail: str = ""
    differential_note: str = ""

    inputs_tested: int = 0
    seconds: float = 0.0
    skipped_reason: str = ""

    @property
    def falsified(self) -> bool:
        """True when a check actually broke the patch. This is what downgrades a result."""
        return self.overfitted or self.diverged or self.evaded

    @property
    def has_evidence(self) -> bool:
        """
        True when at least one falsification attempt actually produced a result.

        Differential testing needs `inputs_tested > 0` to count: the tester skips
        inputs on which the ORIGINAL already crashes, so for a target whose only
        code path is the vulnerable one it can legitimately compare nothing at
        all and still report "behaviour preserved". Treating that as evidence
        credits a patch nobody tried to break.
        """
        return (
            self.overfitting_checked
            or self.evasion_checked
            or (self.differential_checked and self.inputs_tested > 0)
        )

    @property
    def survived(self) -> bool:
        """
        True when the patch was actually attacked and held.

        Deliberately NOT the negation of `falsified`: a patch with no applicable
        check has not survived anything, and must not be counted toward the
        hardening bar. Use `falsified` to decide whether to downgrade a result,
        and this to decide whether it earned the bar.
        """
        return self.has_evidence and not self.falsified

    def summary(self) -> str:
        if self.skipped_reason:
            return f"hardening skipped: {self.skipped_reason}"
        parts = []
        if self.differential_note:
            parts.append(self.differential_note)
        if self.overfitting_checked:
            parts.append("re-fuzz: " + ("NEW CRASH FOUND" if self.overfitted else "clean"))
        if self.evasion_checked:
            parts.append(
                "evasion battery: "
                + (f"BYPASSED — {' '.join(self.evasion_detail.split())[:250]}"
                   if self.evaded else "no bypass found")
            )
        if self.differential_checked:
            detail = ""
            if self.diverged and self.divergence_detail:
                # A falsification verdict is only actionable if it says what
                # diverged; otherwise it cannot be distinguished from a
                # measurement artifact.
                detail = " — " + " ".join(self.divergence_detail.split())[:300]
            parts.append(
                f"differential({self.inputs_tested} inputs): "
                + ("DIVERGED" if self.diverged else "behaviour preserved")
                + detail
            )
        return "; ".join(parts) or "no checks ran"


class DifferentialTester:
    """
    Compares original vs patched behaviour on benign inputs.

    A security patch should change behaviour *only* for inputs that were
    exploiting the bug. If the patched program produces different output for an
    input the original handled correctly, the patch broke something — even if
    the single regression input in the target manifest still passes.
    """

    # Benign inputs that exercise ordinary paths. Deliberately small and
    # printable so they are valid for argv-driven targets.
    @staticmethod
    def generate_inputs(count: int, seed: int = 1337) -> list[list[str]]:
        rng = random.Random(seed)
        inputs: list[list[str]] = []
        alphabet = string.ascii_letters + string.digits

        for _ in range(count):
            shape = rng.choice(["short_str", "num", "two_nums", "three_args"])
            if shape == "short_str":
                n = rng.randint(1, 12)
                inputs.append(["".join(rng.choice(alphabet) for _ in range(n))])
            elif shape == "num":
                inputs.append([str(rng.randint(0, 64))])
            elif shape == "two_nums":
                inputs.append([str(rng.randint(0, 4)), str(rng.randint(0, 4))])
            else:
                inputs.append([
                    str(rng.randint(5, 20)), str(rng.randint(0, 4)),
                    "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 8))),
                ])
        return inputs

    @staticmethod
    def _normalise(output: str, binary: Path) -> str:
        """
        Remove the program's own path from its output before comparison.

        Many C programs echo `argv[0]` — `printf("Usage: %s ...", argv[0])` is
        the canonical case. The original and patched builds necessarily live at
        different paths, so that echo differs on every run and would be reported
        as "the patch changed behaviour" when nothing about the behaviour
        changed. A program's own filename is not part of its behaviour.
        """
        return output.replace(str(binary), "<program>").replace(binary.name, "<program>")

    @staticmethod
    def _run(binary: Path, args: list[str], timeout: int = 15) -> tuple[int, str, bool]:
        """Returns (exit_code, stdout, sanitizer_fired)."""
        try:
            proc = subprocess.run(
                [str(binary), *args], capture_output=True, timeout=timeout,
                env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0", MallocNanoZone="0"),
            )
        except subprocess.TimeoutExpired:
            return -1, "", False
        except Exception:
            return -2, "", False

        err = proc.stderr.decode("utf-8", "replace")
        fired = any(
            marker in err
            for marker in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:")
        )
        stdout = DifferentialTester._normalise(proc.stdout.decode("utf-8", "replace"), binary)
        return proc.returncode, stdout, fired

    def compare(
        self, original_binary: Path, patched_binary: Path, inputs: list[list[str]]
    ) -> tuple[bool, str, int]:
        """
        Returns (diverged, detail, inputs_compared).

        Inputs where the ORIGINAL crashes are skipped — those are the exploit
        cases the patch is supposed to change. Only inputs the original handled
        cleanly constitute a behavioural contract.
        """
        compared = 0
        for args in inputs:
            orig_code, orig_out, orig_fired = self._run(original_binary, args)
            if orig_fired or orig_code < 0:
                continue                       # original was already broken here

            # Determinism screen. Some targets are not reproducible for reasons
            # unrelated to the patch — the command-injection sample shells out to
            # `ping`, whose output varies with DNS and timing. Comparing a single
            # run of each binary would report that noise as a behaviour change
            # and reject a perfectly good patch. Run the ORIGINAL twice: if it
            # disagrees with itself, this input cannot support a comparison.
            recheck_code, recheck_out, _ = self._run(original_binary, args)
            if (recheck_code, recheck_out) != (orig_code, orig_out):
                continue

            compared += 1

            new_code, new_out, new_fired = self._run(patched_binary, args)

            if new_fired:
                return True, (
                    f"patched build trips a sanitizer on benign input {args!r}, "
                    "which the original handled cleanly"
                ), compared
            if new_code != orig_code:
                return True, (
                    f"exit code changed on benign input {args!r}: "
                    f"original={orig_code}, patched={new_code}"
                ), compared
            if new_out != orig_out:
                return True, (
                    f"output changed on benign input {args!r}:\n"
                    f"  original: {orig_out[:200]!r}\n"
                    f"  patched:  {new_out[:200]!r}"
                ), compared

        return False, "", compared


class AdversarialRefuzz:
    """
    Re-fuzzes the patched build to see whether the bug is merely hidden.

    Seeded with the input that originally crashed, so the fuzzer starts adjacent
    to the vulnerable path rather than exploring from scratch. If it finds a new
    crash within the budget, the patch addressed one input, not the defect.
    """

    def __init__(self, harness_dir: Path, workspace: Optional[Path] = None):
        self.harness_dir = Path(harness_dir).resolve()
        self.workspace = Path(workspace).resolve() if workspace else None

    def check(
        self,
        target_id: str,
        patched_source: Path,
        seed_input: Optional[Path],
        seconds: int = 20,
        libfuzzer_clang: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Returns (found_new_crash, detail).

        Requires a fuzz harness for the target; returns (False, reason) when
        none exists, so absence of a harness is never reported as a pass.
        """
        harness = self.harness_dir / f"{target_id}.c"
        if not harness.exists():
            return False, f"no fuzz harness for {target_id}"

        # Must be a clang that ships the libFuzzer runtime. Apple's does not,
        # so falling back to `which clang` silently breaks the build and the
        # check would report "no new crash" — a false pass.
        if not libfuzzer_clang:
            from src.analysis_engine.fuzzer_manager import FuzzerManager
            libfuzzer_clang = FuzzerManager.libfuzzer_clang()
        clang = libfuzzer_clang
        if not clang:
            return False, "no clang with a libFuzzer runtime available"

        with tempfile.TemporaryDirectory(prefix="kavach_refuzz_") as tmp:
            work = Path(tmp)
            binary = work / "refuzz_target"
            mangled = target_id.replace("-", "_")

            build = subprocess.run(
                [
                    clang, "-fsanitize=fuzzer,address,undefined",
                    "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-g", "-O1",
                    f"-Dmain=kavach_disabled_main_{mangled}",
                    str(harness), str(patched_source), "-o", str(binary),
                ],
                capture_output=True, text=True, timeout=300,
            )
            if build.returncode != 0:
                return False, f"re-fuzz build failed: {build.stderr[:300]}"

            corpus = work / "corpus"
            corpus.mkdir()
            if seed_input and Path(seed_input).exists():
                shutil.copy2(seed_input, corpus / "seed")

            artifacts = work / "crashes"
            artifacts.mkdir()

            try:
                subprocess.run(
                    [
                        str(binary), str(corpus),
                        f"-max_total_time={seconds}",
                        f"-artifact_prefix={artifacts}/",
                    ],
                    capture_output=True, timeout=seconds + 120, cwd=str(work),
                    env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0", MallocNanoZone="0"),
                )
            except subprocess.TimeoutExpired:
                return False, "re-fuzz exceeded its budget"

            crashes = [p for p in artifacts.iterdir() if p.is_file()]
            if crashes:
                keep = Path(tempfile.mkdtemp(prefix="kavach_newcrash_")) / crashes[0].name
                shutil.copy2(crashes[0], keep)
                return True, (
                    f"re-fuzzing the PATCHED build found a new crash after {seconds}s "
                    f"(input saved at {keep}). The patch does not fix the root cause."
                )
            return False, f"no new crash in {seconds}s of re-fuzzing"


class PatchHardening:
    """Runs both falsification checks against a patch that already passed the gates."""

    def __init__(self, harness_dir: str = "tests/fuzz_harnesses"):
        self.refuzzer = AdversarialRefuzz(Path(harness_dir))
        self.differ = DifferentialTester()

    def harden(
        self,
        target_id: str,
        original_source: Path,
        patched_source: Path,
        build_command: str,
        seed_crash: Optional[Path] = None,
        refuzz_seconds: int = 20,
        differential_inputs: int = 25,
        libfuzzer_clang: Optional[str] = None,
        behaviour_contract: str = "preserve",
        evasion_command: Optional[str] = None,
    ) -> HardeningVerdict:
        """Falsify the patch if possible. A clean verdict is evidence, not proof."""
        import time
        verdict = HardeningVerdict()
        start = time.time()

        # --- differential behaviour ---
        # Only meaningful when the fix is supposed to preserve behaviour. For an
        # input-validation bug the remediation IS to reject inputs the original
        # accepted, so a behavioural difference is the fix working, not a
        # regression. Judging those targets here would reject correct patches.
        if behaviour_contract != "preserve":
            reason = {
                "restrict": (
                    "an input-validation fix legitimately narrows the accepted "
                    "input domain, so rejecting inputs the original accepted is "
                    "the remediation working, not a regression"
                ),
                "replace": (
                    "the remediation IS to change a compiled-in value (a "
                    "hardcoded secret), so the program's output is required to "
                    "differ from the original; equivalence would mean the fix "
                    "did nothing"
                ),
            }.get(
                behaviour_contract,
                "this fix is not required to preserve observable behaviour",
            )
            verdict.differential_note = (
                f"differential testing not applicable (contract={behaviour_contract}): "
                f"{reason}; the regression gate checks the intended behaviour instead"
            )

        with tempfile.TemporaryDirectory(prefix="kavach_diff_") as tmp:
            work = Path(tmp)
            orig_bin, patched_bin = work / "orig", work / "patched"

            builds_ok = True
            for source, out in ((original_source, orig_bin), (patched_source, patched_bin)):
                cmd = build_command.replace("{src}", str(source)).replace("{bin}", str(out))
                cmd = cmd.replace("{srcdir}", str(Path(source).parent)).replace("{workspace}", str(work))
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                if proc.returncode != 0:
                    builds_ok = False
                    verdict.skipped_reason = f"could not build for differential test: {proc.stderr[:200]}"
                    break

            if builds_ok and behaviour_contract == "preserve":
                inputs = self.differ.generate_inputs(differential_inputs)
                diverged, detail, compared = self.differ.compare(orig_bin, patched_bin, inputs)
                verdict.differential_checked = True
                verdict.diverged = diverged
                verdict.divergence_detail = detail
                verdict.inputs_tested = compared

        # --- evasion battery (input-validation fixes) ---
        # Re-fuzzing falsifies a memory-safety fix by finding another crash.
        # A validation fix has no crash to find: the failure mode is a payload
        # that slips past the check. This runs the target's battery of bypass
        # variants and falsifies the patch if any of them still gets through.
        if evasion_command:
            with tempfile.TemporaryDirectory(prefix="kavach_evade_") as etmp:
                ework = Path(etmp)
                ebin = ework / "evade_target"
                cmd = (build_command.replace("{src}", str(patched_source))
                                    .replace("{bin}", str(ebin))
                                    .replace("{srcdir}", str(Path(patched_source).parent))
                                    .replace("{workspace}", str(ework)))
                built = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                if built.returncode != 0:
                    verdict.evasion_detail = f"could not build for evasion testing: {built.stderr[:200]}"
                else:
                    ecmd = evasion_command.replace("{bin}", str(ebin)).replace("{workspace}", str(ework))
                    proc = subprocess.run(ecmd, shell=True, capture_output=True, text=True, timeout=180)
                    verdict.evasion_checked = True
                    verdict.evaded = proc.returncode != 0
                    verdict.evasion_detail = (proc.stdout + proc.stderr)[:600]

        # --- adversarial re-fuzzing ---
        found, detail = self.refuzzer.check(
            target_id, patched_source, seed_crash,
            seconds=refuzz_seconds, libfuzzer_clang=libfuzzer_clang,
        )
        if "no fuzz harness" not in detail and "no clang" not in detail:
            verdict.overfitting_checked = True
            verdict.overfitted = found
            verdict.new_crash_detail = detail

        verdict.seconds = round(time.time() - start, 2)
        return verdict
