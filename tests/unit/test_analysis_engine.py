"""
Unit tests for the discovery components: fuzzing, crash triage, concolic.

These guard the properties that keep reported results truthful — a crash that
did not reproduce must not become a vulnerability report, distinct bugs must not
be merged, and an unusable concolic engine must not claim results.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analysis_engine.crash_triage import CrashTriage, CrashSignature
from src.analysis_engine.fuzzer_manager import FuzzerManager
from src.analysis_engine.driller_monitor import DrillerEngine, PlateauMonitor


ASAN_HEAP_OVERFLOW = """
=================================================================
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000211
WRITE of size 1 at 0x602000000211 thread T0
    #0 0x102ab in copy_and_null_terminate 06_off_by_one_loop.c:10
    #1 0x102cd in LLVMFuzzerTestOneInput harness.c:14
    #2 0x10999 in fuzzer::Fuzzer::ExecuteCallback FuzzerLoop.cpp:611
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""

ASAN_UAF = """
==124==ERROR: AddressSanitizer: heap-use-after-free on address 0x60b000000040
READ of size 1 at 0x60b000000040 thread T0
    #0 0x1041 in CWE416_Use_After_Free__malloc_free_char_01_bad CWE416.c:12
SUMMARY: AddressSanitizer: heap-use-after-free
"""

UBSAN_OOB = """
11_oob_multidim_array.c:8:12: runtime error: index 1000000 out of bounds for type 'int[5]'
"""

CLEAN_RUN = "Copied string: hi\n"


def test_parses_asan_crash_class_and_location():
    sig = CrashTriage.parse_sanitizer_report(ASAN_HEAP_OVERFLOW)
    assert sig is not None
    assert sig.crash_class == "heap-buffer-overflow"
    assert sig.file_path.endswith("06_off_by_one_loop.c")
    assert sig.line_number == 10
    assert sig.cwe_and_severity == ("CWE-122", "critical")


def test_fuzzer_scaffolding_excluded_from_signature():
    """Engine/harness frames are identical for every crash and must not count."""
    sig = CrashTriage.parse_sanitizer_report(ASAN_HEAP_OVERFLOW)
    joined = " ".join(sig.frames)
    assert "copy_and_null_terminate" in joined
    assert "fuzzer::" not in joined
    assert "LLVMFuzzerTestOneInput" not in joined


def test_ubsan_report_is_parsed():
    sig = CrashTriage.parse_sanitizer_report(UBSAN_OOB)
    assert sig is not None
    assert "out of bounds" in sig.crash_class
    assert sig.line_number == 8


def test_clean_run_is_not_a_vulnerability():
    """An input that does not crash must never become a finding."""
    assert CrashTriage.parse_sanitizer_report(CLEAN_RUN) is None


def test_same_bug_clusters_together_distinct_bugs_do_not():
    same = CrashTriage.parse_sanitizer_report(ASAN_HEAP_OVERFLOW)
    again = CrashTriage.parse_sanitizer_report(ASAN_HEAP_OVERFLOW)
    other = CrashTriage.parse_sanitizer_report(ASAN_UAF)
    assert same.digest == again.digest
    assert same.digest != other.digest


def test_crash_class_maps_to_cwe():
    assert CrashSignature(crash_class="heap-use-after-free").cwe_and_severity[0] == "CWE-416"
    assert CrashSignature(crash_class="double-free").cwe_and_severity[0] == "CWE-415"
    assert CrashSignature(crash_class="totally-unknown-thing").cwe_and_severity[0] == ""


def test_plateau_detection():
    monitor = PlateauMonitor("unused")
    assert monitor.is_plateaued([10, 11, 12, 12, 12, 12])      # stalled
    assert not monitor.is_plateaued([10, 11, 12, 13, 14, 15])  # still finding paths
    assert not monitor.is_plateaued([12, 12])                  # not enough samples


def test_driller_self_test_gates_reporting():
    """
    Driller must only claim results when angr provably solves a known answer on
    this platform. Whichever way the self-test goes, the outcome must carry a
    reason and must agree with what drill() does.
    """
    ok, reason = DrillerEngine.self_test()
    assert isinstance(ok, bool)
    assert reason, "self-test must always explain its verdict"

    if not ok:
        result = DrillerEngine().drill("/bin/ls", b"seed", timeout_seconds=5)
        assert result.supported is False
        assert result.new_inputs == [], "an unusable engine must not emit inputs"
        assert result.reason


def test_fuzzer_engine_detection_is_honest():
    """available_engines() must only list engines that can really be used."""
    fm = FuzzerManager("benchmark_workspace/fuzzing")
    engines = fm.available_engines()
    assert set(engines).issubset({"libfuzzer", "afl++"})
    if "libfuzzer" in engines:
        assert fm.libfuzzer_clang() is not None
    if "afl++" in engines:
        assert fm.afl_available()


def test_missing_harness_reports_error_not_crash():
    fm = FuzzerManager("benchmark_workspace/fuzzing")
    binary, error = fm.build("NO-SUCH-TARGET", "tests/demo_vulns/06_off_by_one_loop.c", "libfuzzer")
    assert binary is None
    assert "no fuzz harness" in error


# --- fuzz-discovery PoV gate ---------------------------------------------
# A gate command that cannot resolve its own paths fails for mechanical
# reasons and gets recorded as "the patch didn't fix it" — silently turning a
# broken harness into a false negative. These tests pin the paths down.

from src.fuzz_pipeline import FuzzDiscoveryPipeline, HARNESS_DIR


def test_harness_dir_is_absolute():
    """Gate commands run with cwd set to a temp workspace, not the repo root."""
    assert HARNESS_DIR.is_absolute()


def test_pov_command_uses_only_absolute_paths(tmp_path):
    """
    Every file the PoV command references must be absolute, except the
    {workspace}/{src} placeholders the DRV loop substitutes at run time.
    """
    crash = tmp_path / "crash-input"
    crash.write_bytes(b"A" * 8)
    fuzz_binary = tmp_path / "SYN-02-DEEP-TYPEDEF" / "libfuzzer" / "fuzz_target"
    fuzz_binary.parent.mkdir(parents=True)
    fuzz_binary.touch()

    cmd = FuzzDiscoveryPipeline._pov_command(str(fuzz_binary), str(crash))

    # Pull out every quoted path and check it is absolute or a placeholder.
    import re
    for quoted in re.findall(r'"([^"]+)"', cmd):
        if quoted.startswith("{") or quoted.startswith("-"):
            continue
        assert quoted.startswith("/"), f"relative path in PoV command: {quoted}"

    assert str(crash) in cmd
    assert "SYN-02-DEEP-TYPEDEF.c" in cmd      # the matching harness
    assert "afl_driver.c" in cmd
    assert "pov_run.sh" in cmd
