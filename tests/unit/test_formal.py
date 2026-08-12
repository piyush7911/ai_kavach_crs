"""
Tests for bounded formal verification (CBMC).

The reason this component exists is the first test below: it catches an
overfitted patch that the dynamic PoV gate passes. If that test ever stops
holding, the component is not earning its place and should be removed rather
than kept for appearance.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.patch_validator.formal import FormalVerifier, VerificationResult

HARNESSES = Path(__file__).parent.parent / "benchmarks" / "cbmc_harnesses"
DEMOS = Path(__file__).parent.parent / "demo_vulns"

pytestmark = pytest.mark.skipif(
    shutil.which("cbmc") is None, reason="cbmc required (brew install cbmc)"
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


# --- the justification for this component ---------------------------------

def test_catches_overfitted_patch_that_the_pov_gate_passes(tmp_path):
    """
    A patch that special-cases the exact PoV input satisfies build + PoV +
    regression, because the one input we replay no longer crashes. CBMC reasons
    over ALL inputs, so it still finds the violation.

    SYN-11 has no fuzz harness either, so adversarial re-fuzzing cannot cover
    this target — formal verification is the only check that catches it.
    """
    src = (DEMOS / "11_oob_multidim_array.c").read_text()
    overfitted = src.replace(
        "    if (row < 0 || row >= 5) {",
        "    if (col == 1000000) return -1;\n    if (row < 0 || row >= 5) {",
    )
    assert overfitted != src, "overfit fixture failed to apply"
    patched = _write(tmp_path, "over.c", overfitted)

    # The dynamic gate is satisfied by the cheat.
    binary = tmp_path / "bin"
    subprocess.run(
        f'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O0 '
        f'"{patched}" -o "{binary}"', shell=True, check=True, capture_output=True)
    pov = subprocess.run(
        f'sh "{Path(__file__).parent.parent}/benchmarks/harness/pov_run.sh" '
        f'"{binary}" "0" "1000000"', shell=True, capture_output=True)
    assert pov.returncode == 0, "precondition: the PoV gate must pass the cheat"

    # Formal verification is not.
    result = FormalVerifier().verify_patched(
        patched, HARNESSES / "SYN-11-OOB-MULTIDIM.c", tmp_path, unwind=16)
    assert result.status == "violated", (
        "formal verification failed to catch an overfitted patch — if this "
        "holds, the component adds nothing over the dynamic gates"
    )
    assert any("array_bounds" in v for v in result.violations)


# --- discrimination --------------------------------------------------------

@pytest.mark.parametrize("target,source,old,new,unwind", [
    ("SYN-11-OOB-MULTIDIM", "11_oob_multidim_array.c",
     "if (row < 0 || row >= 5) {",
     "if (row < 0 || row >= 5 || col < 0 || col >= 5) {", 16),
    ("SYN-12-INT-UNDERFLOW", "12_integer_underflow.c",
     "    size_t length = chunk_end - chunk_start; ",
     "    if (chunk_end < chunk_start) return;\n    size_t length = chunk_end - chunk_start; ", 20),
    ("SYN-06-OFF-BY-ONE", "06_off_by_one_loop.c",
     "char* dest = (char*)malloc(size);",
     "char* dest = (char*)malloc(size + 1);", 70),
])
def test_violated_on_original_and_proven_on_fix(target, source, old, new, unwind, tmp_path):
    """Each harness must separate the vulnerable original from a correct fix."""
    fv = FormalVerifier()
    harness = HARNESSES / f"{target}.c"
    original = DEMOS / source

    before = fv.verify_patched(original, harness, tmp_path, unwind=unwind)
    assert before.status == "violated", f"{target}: original should violate, got {before.status}"

    text = original.read_text()
    assert old in text, f"{target}: fixture anchor missing"
    fixed = _write(tmp_path, f"fixed_{source}", text.replace(old, new))

    after = fv.verify_patched(fixed, harness, tmp_path, unwind=unwind)
    assert after.status == "proven", f"{target}: fix should verify, got {after.status} ({after.detail})"
    assert after.unwind == unwind
    assert after.properties_checked > 0


# --- honest reporting ------------------------------------------------------

def test_missing_harness_reports_unavailable_not_proven(tmp_path):
    """Absence of a proof must never read as a proof."""
    src = _write(tmp_path, "x.c", "int f(void){return 0;}\n")
    r = FormalVerifier().verify_patched(src, tmp_path / "no_such_harness.c", tmp_path)
    assert r.status == "unavailable"
    assert not r.proven
    assert "harness" in r.detail


def test_proven_property_requires_clean_status():
    assert VerificationResult(status="proven").proven
    for bad in ("violated", "inconclusive", "unavailable"):
        assert not VerificationResult(status=bad).proven


def test_summary_states_the_bound():
    """A bounded proof must never be reported without its bound."""
    r = VerificationResult(status="proven", unwind=32, properties_checked=10)
    assert "unwind=32" in r.summary()


def test_main_is_stripped_before_verification():
    """
    Verifying main() with unconstrained argv fails inside CBMC's libc models
    even for a correct patch, so main must not reach the solver.
    """
    text = "int helper(int x){return x;}\nint main(int argc, char**argv){return helper(argc);}\n"
    stripped = FormalVerifier.strip_main(text)
    assert "helper" in stripped
    assert "int main(" not in stripped


@pytest.mark.parametrize("text,keep", [
    ("int helper(int x){return x;}\nint main(int argc, char**argv){return helper(argc);}\n", "helper"),
    ("int f(void){return 1;}\nint main(void) {\n  int a = 1;\n  if (a) { a++; }\n  return a;\n}\n", "int f(void)"),
    ('int g(void){return 2;}\nint main(void){ printf("}"); return 0; }\n', "int g(void)"),   # brace in a string
    ("int h(void){return 3;}\nint main(void){ /* } */ return 0; }\n", "int h(void)"),        # brace in a comment
    ("int only(void){return 4;}\n", "int only(void)"),                                       # no main at all
])
def test_strip_main_handles_real_c(text, keep):
    """
    Brace matching, not a regex: a single-line main, or a brace inside a string
    or comment, must not defeat it. Leaving main in place sends unconstrained
    argv to CBMC, whose libc models then fail on correct patches.
    """
    stripped = FormalVerifier.strip_main(text)
    assert keep in stripped
    assert "main" not in stripped or "int only" in stripped


def test_strip_main_leaves_unbalanced_source_untouched():
    """Truncating a malformed file would be worse than not stripping."""
    broken = "int main(void){ if (1) {  \n"
    assert FormalVerifier.strip_main(broken) == broken
