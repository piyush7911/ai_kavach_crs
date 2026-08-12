"""
AI Kavach CRS — Bounded formal verification (CBMC)

Every other check in this system is *empirical*: it runs the program on inputs
we chose and observes what happens. A sanitizer sees only the paths actually
executed; a fuzzer sees only the inputs it generated. Neither can say anything
about the inputs nobody tried.

CBMC is different in kind. It compiles the function into a bit-precise logical
formula and asks an SMT solver whether any assignment of the inputs violates a
safety property. A `VERIFICATION SUCCESSFUL` result is a statement about *all*
inputs — within an unwind bound.

What this does and does not claim
---------------------------------
The claim is **bounded proof**, never "correct":

  * Loops are unwound `unwind` times. A counterexample needing more iterations
    is not explored, so `SUCCESSFUL` means "no violation exists within this
    bound", not "no violation exists".
  * `--unwinding-assertions` makes CBMC *report* when a loop could not be fully
    unwound, so an insufficient bound is visible rather than silently assumed.
    `VerificationResult.bound_exhausted` records this, and a result with an
    unproven unwinding assertion is reported as INCONCLUSIVE, not proven.
  * It checks the properties requested (bounds, pointer safety, arithmetic
    overflow, division by zero) and nothing else.

Measured limitations on this corpus
-----------------------------------
These were established by running CBMC, not assumed from documentation:

  * **Whole-program runs are not usable.** Verifying `main()` with unconstrained
    `argv` produces failures inside CBMC's model of libc (`strtol` dereferences,
    unwinding assertions), and those failures persist on a *correctly patched*
    file. Verification must target a proof harness over the vulnerable function.
  * **It is not a superset of AddressSanitizer.** For SYN-18, `memcpy` into a
    struct member is checked at object granularity — writing 100 bytes into the
    ~104-byte enclosing struct verifies as SAFE, exactly as ASan treats it. CBMC
    complements the sanitizers; it does not replace them.

Because of the first point, a target must supply a harness to be formally
verified. Absence of a harness yields `unavailable`, never a pass.
"""

import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Safety properties CBMC is asked to prove. Each maps to a class of defect the
# corpus actually contains.
DEFAULT_CHECKS = (
    "--bounds-check",              # array index out of range
    "--pointer-check",             # invalid / null / out-of-object dereference
    "--conversion-check",          # lossy integer conversion (truncation)
    "--signed-overflow-check",     # signed arithmetic overflow
    "--unsigned-overflow-check",   # unsigned wrap-around
    "--div-by-zero-check",
    "--unwinding-assertions",      # tell us when the bound was insufficient
)

_VERDICT = re.compile(r"^VERIFICATION (SUCCESSFUL|FAILED)", re.M)
_FAILURE = re.compile(r"^\[([^\]]+)\]\s+(.*?):\s*FAILURE\s*$", re.M)


@dataclass
class VerificationResult:
    """Outcome of one CBMC run. Every field reflects observed output."""

    status: str = "unavailable"      # proven | violated | inconclusive | unavailable
    unwind: int = 0
    properties_checked: int = 0
    violations: list[str] = field(default_factory=list)
    bound_exhausted: bool = False    # an unwinding assertion failed
    seconds: float = 0.0
    detail: str = ""

    @property
    def proven(self) -> bool:
        """True only for a clean proof within a fully explored bound."""
        return self.status == "proven"

    def summary(self) -> str:
        if self.status == "unavailable":
            return f"formal: not attempted — {self.detail}"
        if self.status == "proven":
            return (
                f"formal: PROVEN within unwind={self.unwind} "
                f"({self.properties_checked} properties, no violation)"
            )
        if self.status == "violated":
            first = self.violations[0] if self.violations else "unspecified"
            return f"formal: VIOLATED — {first[:150]}"
        return f"formal: INCONCLUSIVE — {self.detail}"


class FormalVerifier:
    """Runs CBMC against a proof harness for one target."""

    def __init__(self, unwind: int = 16, timeout: int = 180):
        self.unwind = unwind
        self.timeout = timeout

    @staticmethod
    def available() -> tuple[bool, str]:
        try:
            r = subprocess.run(["cbmc", "--version"], capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return True, f"cbmc {r.stdout.strip()}"
            return False, "cbmc present but did not report a version"
        except FileNotFoundError:
            return False, "cbmc not installed (brew install cbmc)"
        except Exception as e:
            return False, f"cbmc probe failed: {e}"

    def verify(
        self,
        source: Path,
        harness: Path,
        entry: str = "harness",
        unwind: Optional[int] = None,
        extra_checks: tuple = (),
    ) -> VerificationResult:
        """
        Prove the harness's safety properties over the (possibly patched) source.

        `source` must not define `main`: CBMC would then verify the whole
        program with unconstrained argv, which produces libc-model failures that
        survive a correct patch. The caller strips it via `strip_main`.
        """
        import time
        start = time.time()
        unwind = unwind or self.unwind
        result = VerificationResult(unwind=unwind)

        ok, detail = self.available()
        if not ok:
            result.detail = detail
            return result
        if not harness.exists():
            result.detail = f"no proof harness for this target ({harness.name})"
            return result

        cmd = [
            "cbmc", *DEFAULT_CHECKS, *extra_checks,
            "--unwind", str(unwind),
            "--function", entry,
            str(harness), str(source),
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            result.status = "inconclusive"
            result.detail = f"cbmc exceeded {self.timeout}s at unwind={unwind}"
            result.seconds = round(time.time() - start, 2)
            return result
        except Exception as e:
            result.detail = f"cbmc invocation failed: {e}"
            result.seconds = round(time.time() - start, 2)
            return result

        out = proc.stdout + proc.stderr
        result.seconds = round(time.time() - start, 2)
        result.properties_checked = out.count(": SUCCESS") + out.count(": FAILURE")

        failures = [f"{name} {desc}".strip() for name, desc in _FAILURE.findall(out)]
        result.violations = failures
        result.bound_exhausted = any("unwinding assertion" in f for f in failures)

        verdict = _VERDICT.search(out)
        if not verdict:
            result.status = "inconclusive"
            result.detail = (
                "cbmc produced no verdict — the harness may not link against the "
                f"target (first lines: {out.strip().splitlines()[:2]})"
            )
            return result

        if verdict.group(1) == "SUCCESSFUL":
            result.status = "proven"
            return result

        # FAILED. Distinguish "the bound was too small to decide" from "a real
        # violation exists" — reporting the former as a violation would blame a
        # patch for our own configuration.
        real = [f for f in failures if "unwinding assertion" not in f]
        if not real and result.bound_exhausted:
            result.status = "inconclusive"
            result.detail = (
                f"unwind={unwind} was insufficient to fully explore the loops; "
                "no violation found within it, but the bound was not exhausted"
            )
        else:
            result.status = "violated"
            result.detail = f"{len(real)} property violation(s)"
        return result

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def strip_main(source_text: str) -> str:
        """
        Remove `main` so CBMC verifies only the harness entry point.

        Whole-program verification with unconstrained argv fails inside CBMC's
        libc models regardless of the patch, so `main` must not be present.

        Brace matching rather than a regex: a regex anchored on a newline before
        the closing brace silently leaves a single-line `main` in place, and the
        resulting run produces libc-model failures that look like real
        violations. Silent failure here is worse than no stripping at all.
        """
        match = re.search(r'\b(?:int|void)\s+main\s*\([^)]*\)\s*\{', source_text)
        if not match:
            return source_text

        depth, i = 0, match.end() - 1        # start at the opening brace
        in_string = in_char = in_line_comment = in_block_comment = False

        while i < len(source_text):
            c = source_text[i]
            nxt = source_text[i + 1] if i + 1 < len(source_text) else ""

            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if c == "*" and nxt == "/":
                    in_block_comment = False
                    i += 1
            elif in_string:
                if c == "\\":
                    i += 1
                elif c == '"':
                    in_string = False
            elif in_char:
                if c == "\\":
                    i += 1
                elif c == "'":
                    in_char = False
            else:
                if c == "/" and nxt == "/":
                    in_line_comment = True
                    i += 1
                elif c == "/" and nxt == "*":
                    in_block_comment = True
                    i += 1
                elif c == '"':
                    in_string = True
                elif c == "'":
                    in_char = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return source_text[:match.start()] + source_text[i + 1:]
            i += 1

        # Unbalanced braces: return unchanged rather than truncate the file.
        logger.warning("strip_main: unbalanced braces; leaving source unmodified")
        return source_text

    def verify_patched(
        self, patched_source: Path, harness: Path, workspace: Path, **kw
    ) -> VerificationResult:
        """Strip `main` into a scratch copy, then verify."""
        try:
            text = self.strip_main(patched_source.read_text())
        except Exception as e:
            r = VerificationResult()
            r.detail = f"could not read patched source: {e}"
            return r
        scratch = workspace / f"cbmc_{patched_source.name}"
        scratch.write_text(text)
        return self.verify(scratch, harness, **kw)


def make_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="kavach_cbmc_"))
