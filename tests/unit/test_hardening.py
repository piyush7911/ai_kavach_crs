"""
Tests for patch hardening.

The critical cases here are the two cheats that defeat gate-only verification:
a patch that special-cases the crashing input, and a patch that disables the
code path. Both pass build + PoV + regression. These tests assert that
hardening catches them — if they ever start passing, our accuracy numbers
become meaningless.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.patch_validator.hardening import (
    DifferentialTester, AdversarialRefuzz, PatchHardening, HardeningVerdict,
)

BUILD = 'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 "{src}" -o "{bin}"'

# A program that behaves CORRECTLY for short inputs and overflows for long ones.
# This matters: a program that crashes on every input has no benign behaviour,
# so differential testing would have nothing to compare.
VULNERABLE = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_it(const char* src, size_t size) {
    char* dest = (char*)malloc(64);
    if (!dest) return;
    for (size_t i = 0; i < size; i++) dest[i] = src[i];   /* overflows when size > 64 */
    dest[size < 64 ? size : 63] = '\\0';
    printf("copied:%s\\n", dest);
    free(dest);
}
int main(int argc, char** argv) {
    if (argc > 1) copy_it(argv[1], strlen(argv[1]));
    return 0;
}
"""

# The honest fix: size the allocation to the input.
CORRECT = VULNERABLE.replace(
    "    char* dest = (char*)malloc(64);",
    "    char* dest = (char*)malloc(size + 1);",
).replace(
    "    dest[size < 64 ? size : 63] = '\\0';",
    "    dest[size] = '\\0';",
)

# Cheat 1 — silences ONLY the known proof-of-vulnerability length. Every other
# length still overflows, so re-fuzzing must expose it.
OVERFITTED = VULNERABLE.replace(
    "    for (size_t i = 0; i < size; i++)",
    "    if (size == 80) size = 63;   /* silence the known PoV only */\n"
    "    for (size_t i = 0; i < size; i++)",
)

# Cheat 2 — disables the function entirely. Passes any single-input regression
# check, but changes behaviour for every benign input.
GUTTED = VULNERABLE.replace(
    "    char* dest = (char*)malloc(64);",
    "    return;\n    char* dest = (char*)malloc(64);",
)
assert GUTTED != VULNERABLE, "GUTTED fixture failed to apply — the test would be vacuous"
assert CORRECT != VULNERABLE, "CORRECT fixture failed to apply"
assert OVERFITTED != VULNERABLE, "OVERFITTED fixture failed to apply"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _build(source: Path, out: Path) -> bool:
    cmd = BUILD.replace("{src}", str(source)).replace("{bin}", str(out))
    return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="clang required")


# --- differential testing --------------------------------------------------

def test_correct_patch_preserves_behaviour(tmp_path):
    """The honest fix must NOT be flagged — no false positives."""
    orig, patched = _write(tmp_path, "o.c", VULNERABLE), _write(tmp_path, "p.c", CORRECT)
    ob, pb = tmp_path / "ob", tmp_path / "pb"
    assert _build(orig, ob) and _build(patched, pb)

    inputs = DifferentialTester.generate_inputs(20)
    diverged, detail, compared = DifferentialTester().compare(ob, pb, inputs)
    assert not diverged, f"correct patch wrongly flagged: {detail}"


def test_gutted_patch_is_caught(tmp_path):
    """A patch that disables the code path passes the gates but changes behaviour."""
    orig, patched = _write(tmp_path, "o.c", VULNERABLE), _write(tmp_path, "p.c", GUTTED)
    ob, pb = tmp_path / "ob", tmp_path / "pb"
    assert _build(orig, ob) and _build(patched, pb)

    inputs = DifferentialTester.generate_inputs(20)
    diverged, detail, _ = DifferentialTester().compare(ob, pb, inputs)
    assert diverged, "a patch that guts the function must be caught"
    assert "output changed" in detail or "exit code changed" in detail


def test_inputs_where_original_crashes_are_not_compared(tmp_path):
    """
    The original here crashes on every non-empty input, so there is no benign
    behaviour to preserve and nothing should be compared or flagged.
    """
    orig, patched = _write(tmp_path, "o.c", VULNERABLE), _write(tmp_path, "p.c", CORRECT)
    ob, pb = tmp_path / "ob", tmp_path / "pb"
    assert _build(orig, ob) and _build(patched, pb)

    diverged, _, compared = DifferentialTester().compare(
        ob, pb, [["A" * 100], ["B" * 150]]      # both overflow the original
    )
    assert not diverged
    assert compared == 0, "crashing inputs must be excluded from the contract"


def test_generated_inputs_are_deterministic():
    assert DifferentialTester.generate_inputs(10) == DifferentialTester.generate_inputs(10)


# --- adversarial re-fuzzing ------------------------------------------------

def test_refuzz_reports_missing_harness_rather_than_passing(tmp_path):
    """Absence of a harness must never be reported as 'patch is fine'."""
    refuzzer = AdversarialRefuzz(tmp_path)
    found, detail = refuzzer.check("NO-SUCH-TARGET", tmp_path / "x.c", None, seconds=1)
    assert found is False
    assert "no fuzz harness" in detail


def test_overfitted_patch_is_caught_by_refuzzing(tmp_path):
    """
    The core anti-gaming test. OVERFITTED silences exactly the size-80 PoV; the
    bug is still reachable at any other length, so re-fuzzing must find it.
    """
    harness_dir = tmp_path / "harnesses"
    harness_dir.mkdir()
    (harness_dir / "TGT.c").write_text("""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
void copy_it(const char* src, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 200) return 0;
    char* s = (char*)malloc(size + 1);
    memcpy(s, data, size); s[size] = 0;
    copy_it(s, size);
    free(s);
    return 0;
}
""")
    patched = _write(tmp_path, "overfitted.c", OVERFITTED)
    found, detail = AdversarialRefuzz(harness_dir).check(
        "TGT", patched, seed_input=None, seconds=15,
    )
    assert found, f"re-fuzzing failed to expose an overfitted patch: {detail}"
    assert "new crash" in detail.lower()


def test_correct_patch_survives_refuzzing(tmp_path):
    """No false positive: the honest fix should withstand re-fuzzing."""
    harness_dir = tmp_path / "harnesses"
    harness_dir.mkdir()
    (harness_dir / "TGT.c").write_text("""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
void copy_it(const char* src, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 200) return 0;
    char* s = (char*)malloc(size + 1);
    memcpy(s, data, size); s[size] = 0;
    copy_it(s, size);
    free(s);
    return 0;
}
""")
    patched = _write(tmp_path, "correct.c", CORRECT)
    found, detail = AdversarialRefuzz(harness_dir).check(
        "TGT", patched, seed_input=None, seconds=15,
    )
    assert not found, f"correct patch wrongly flagged as overfitted: {detail}"


# --- verdict semantics -----------------------------------------------------

def test_verdict_survived_requires_both_checks_clean():
    """A clean verdict must come from a check that actually ran."""
    assert not HardeningVerdict().survived, (
        "an empty verdict means nothing was attempted, not that the patch held"
    )
    assert HardeningVerdict(overfitting_checked=True).survived
    assert not HardeningVerdict(overfitting_checked=True, overfitted=True).survived
    assert not HardeningVerdict(differential_checked=True, inputs_tested=9, diverged=True).survived


def test_falsified_and_survived_are_not_opposites():
    """
    `falsified` decides whether to downgrade a result; `survived` decides
    whether it earned the hardening bar. A patch nothing could test is neither.
    """
    nothing_ran = HardeningVerdict()
    assert not nothing_ran.falsified, "no check ran, so nothing was disproved"
    assert not nothing_ran.survived, "no check ran, so nothing was proved either"


def test_zero_input_differential_is_not_evidence():
    """
    The differ skips inputs on which the ORIGINAL crashes, so a target whose
    only code path is the vulnerable one yields "differential(0 inputs):
    behaviour preserved". Counting that as survival credits a patch that nobody
    managed to attack — SYN-16 produced exactly this verdict.
    """
    vacuous = HardeningVerdict(differential_checked=True, inputs_tested=0)
    assert not vacuous.has_evidence
    assert not vacuous.survived

    real = HardeningVerdict(differential_checked=True, inputs_tested=1)
    assert real.has_evidence and real.survived


def test_verdict_summary_mentions_what_ran():
    v = HardeningVerdict(overfitting_checked=True, differential_checked=True, inputs_tested=12)
    text = v.summary()
    assert "re-fuzz" in text and "differential" in text and "12" in text


# --- harness fairness ------------------------------------------------------
# A harness that passes a count/length exceeding the buffer it supplies makes
# the target unfixable by contract: no patch confined to that function can stop
# the resulting out-of-bounds read. That produces FALSE hardening failures and
# blames the agent for our bug. It happened once; this test stops it recurring.

def test_harnesses_do_not_violate_buffer_preconditions():
    harness_dir = Path(__file__).parent.parent / "fuzz_harnesses"
    offenders = []

    for harness in harness_dir.glob("*.c"):
        if harness.name == "afl_driver.c":
            continue
        text = harness.read_text()

        # SYN-12-style: a modulo bound on the requested length must not exceed
        # the size of the backing buffer.
        import re
        mod_bounds = [int(m) for m in re.findall(r"%\s*(\d+)", text)]
        buf_sizes = [int(m) for m in re.findall(r"backing\[(\d+)\]", text)]
        if mod_bounds and buf_sizes and max(mod_bounds) > max(buf_sizes):
            offenders.append(
                f"{harness.name}: requests up to {max(mod_bounds)} bytes "
                f"from a {max(buf_sizes)}-byte buffer"
            )

        # calloc(N, S) backing a caller-supplied count must not be paired with
        # an unbounded count.
        calloc = re.search(r"calloc\((\d+),\s*(\d+)\)", text)
        shift = re.search(r"count\s*>\s*\(1u?\s*<<\s*(\d+)\)", text)
        if calloc and shift:
            records = int(calloc.group(1))
            max_count = 1 << int(shift.group(1))
            if max_count > records:
                offenders.append(
                    f"{harness.name}: allows count up to {max_count} "
                    f"with only {records} records allocated"
                )

    assert not offenders, "harness violates a target's precondition:\n" + "\n".join(offenders)


# --- determinism screening -------------------------------------------------
# Differential testing assumes the program is reproducible. Targets that shell
# out, use the network, or read the clock are not. Without screening, that noise
# is reported as "the patch changed behaviour" and a good patch is rejected.
# This is not hypothetical: it fired on the command-injection target, which runs
# `ping` via system().

NONDETERMINISTIC = """#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(int argc, char** argv) {
    (void)argv;
    srand((unsigned)time(NULL) ^ (unsigned)clock());
    printf("value:%d\\n", rand());
    return argc > 1 ? 0 : 0;
}
"""


def test_nondeterministic_target_is_not_flagged(tmp_path):
    """A program that disagrees with itself must be skipped, not reported."""
    src = _write(tmp_path, "nd.c", NONDETERMINISTIC)
    a, b = tmp_path / "a", tmp_path / "b"
    assert _build(src, a) and _build(src, b)

    inputs = DifferentialTester.generate_inputs(8)
    diverged, detail, compared = DifferentialTester().compare(a, b, inputs)

    assert not diverged, f"non-determinism reported as divergence: {detail}"
    assert compared == 0, "non-reproducible inputs must not enter the comparison"


def test_deterministic_target_still_compares(tmp_path):
    """The screen must not silently disable comparison for well-behaved targets."""
    orig, patched = _write(tmp_path, "o.c", VULNERABLE), _write(tmp_path, "p.c", GUTTED)
    ob, pb = tmp_path / "ob", tmp_path / "pb"
    assert _build(orig, ob) and _build(patched, pb)

    diverged, _, compared = DifferentialTester().compare(
        ob, pb, DifferentialTester.generate_inputs(20)
    )
    assert compared > 0, "deterministic inputs must still be compared"
    assert diverged


# --- argv[0] normalisation -------------------------------------------------
# Programs commonly echo their own path (`printf("Usage: %s", argv[0])`). The
# original and patched builds necessarily live at different paths, so that echo
# differs on every run. Without normalisation it is reported as "the patch
# changed behaviour" — which falsified two otherwise-correct patches.

ECHOES_ARGV0 = """#include <stdio.h>
int main(int argc, char** argv) {
    if (argc < 3) { printf("Usage: %s <a> <b>\\n", argv[0]); return 1; }
    printf("ok:%s,%s\\n", argv[1], argv[2]);
    return 0;
}
"""


def test_argv0_echo_is_not_a_behaviour_change(tmp_path):
    """Identical source built at two paths must compare as identical."""
    src = _write(tmp_path, "u.c", ECHOES_ARGV0)
    orig, patched = tmp_path / "orig", tmp_path / "patched"
    assert _build(src, orig) and _build(src, patched)

    diverged, detail, compared = DifferentialTester().compare(
        orig, patched, DifferentialTester.generate_inputs(20)
    )
    assert not diverged, f"argv[0] echo reported as divergence: {detail}"
    assert compared > 0, "usage-printing inputs should still be compared"


def test_normalisation_does_not_mask_real_output_changes(tmp_path):
    """The fix must not blind the tester to genuine behavioural differences."""
    changed = ECHOES_ARGV0.replace('printf("ok:%s,%s\\n"', 'printf("CHANGED:%s,%s\\n"')
    assert changed != ECHOES_ARGV0
    a = _write(tmp_path, "a.c", ECHOES_ARGV0)
    b = _write(tmp_path, "b.c", changed)
    orig, patched = tmp_path / "orig2", tmp_path / "patched2"
    assert _build(a, orig) and _build(b, patched)

    diverged, detail, _ = DifferentialTester().compare(
        orig, patched, DifferentialTester.generate_inputs(20)
    )
    assert diverged, "a real output change must still be caught"
    assert "output changed" in detail


# --- hardening labels ------------------------------------------------------
# The label is what ends up in a report, so it must never overstate. In
# particular "SURVIVED" has to mean a falsification attempt actually ran and
# failed — not that nothing was tried.

from tests.standalone_support import hardening_label


def test_survived_requires_a_check_to_have_run():
    assert hardening_label(HardeningVerdict()) == "NOT HARDENED"
    assert hardening_label(
        HardeningVerdict(skipped_reason="could not re-apply patch")
    ) == "NOT HARDENED"


def test_each_falsification_channel_is_reported():
    assert "overfitted" in hardening_label(
        HardeningVerdict(overfitting_checked=True, overfitted=True))
    assert "bypassed" in hardening_label(
        HardeningVerdict(evasion_checked=True, evaded=True)).lower()
    assert "behaviour changed" in hardening_label(
        HardeningVerdict(differential_checked=True, diverged=True))


def test_evasion_battery_alone_counts_as_hardened():
    """
    For an input-validation fix the battery is the ONLY applicable check:
    re-fuzzing has no crash to find and differential testing cannot judge a
    deliberately narrowed input domain. Ignoring it reported a genuinely
    hardened patch as unhardened.
    """
    assert hardening_label(HardeningVerdict(evasion_checked=True)) == "SURVIVED"


def test_evasion_failure_makes_verdict_not_survived():
    assert not HardeningVerdict(evasion_checked=True, evaded=True).survived


# --- PoV feedback quality ---------------------------------------------------
# The DRV loop feeds the PoV gate's output back to the repair agent, and Agent
# Delta diagnoses from it. pov_run.sh captured the sanitizer report and then
# discarded it, so every PoV failure reached the agents as "your patch still
# crashes" with a blank report.

def test_pov_runner_emits_the_sanitizer_report_on_failure(tmp_path):
    """A failing PoV must return the diagnostic, not just a non-zero exit."""
    src = _write(tmp_path, "crash.c", """
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* p[0] is printed so the write is not dead-store eliminated at -O1. */
int main(void){ char*p=malloc(4); memset(p,'A',64); printf("%c", p[0]); free(p); return 0; }
""")
    binary = tmp_path / "crash"
    # -O0 explicitly: at -O1 the compiler shrinks the 64-byte memset to the one
    # byte that is actually read, and the overflow disappears.
    assert subprocess.run(
        f'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O0 '
        f'"{src}" -o "{binary}"', shell=True, capture_output=True).returncode == 0

    runner = Path(__file__).parent.parent / "benchmarks" / "harness" / "pov_run.sh"
    r = subprocess.run(["sh", str(runner), str(binary)], capture_output=True, text=True)

    assert r.returncode == 1, "vulnerable binary must fail the PoV gate"
    combined = r.stdout + r.stderr
    assert "AddressSanitizer" in combined, "the sanitizer report must reach the agent"
    assert "heap-buffer-overflow" in combined, "the crash class must reach the agent"


def test_pov_runner_stays_quiet_on_success(tmp_path):
    """A passing PoV should not spam the log with output."""
    src = _write(tmp_path, "ok.c", "int main(void){ return 0; }\n")
    binary = tmp_path / "ok"
    assert _build(src, binary)
    runner = Path(__file__).parent.parent / "benchmarks" / "harness" / "pov_run.sh"
    r = subprocess.run(["sh", str(runner), str(binary)], capture_output=True, text=True)
    assert r.returncode == 0
