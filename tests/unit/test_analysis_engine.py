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


# ---------------------------------------------------------------------------
# Crash attribution under inlining
#
# These pin the three defects that made a real fuzzer-discovered double-free
# (SYN-05) unrepairable: the pipeline skipped it as "crash location unresolved"
# because triage blamed libFuzzer instead of the target.
# ---------------------------------------------------------------------------

# Verbatim shape of the report SYN-05 produces at -O1, where `process_data` is
# inlined into the harness so the faulting frame is scaffolding and the target
# appears only in the "freed by" stack.
_INLINED_DOUBLE_FREE = """\
==11682==ERROR: AddressSanitizer: attempting double-free on 0x60c000000ac0 in thread T0:
    #0 0x0001010d8f10 in free+0x74 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x54f10)
    #1 0x0001009c0b14 in LLVMFuzzerTestOneInput SYN-05-DOUBLE-FREE.c:16
    #2 0x0001009dca28 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) FuzzerLoop.cpp:619
    #3 0x0001009ce56c in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) FuzzerDriver.cpp:871
    #4 0x0001009f9074 in main FuzzerMain.cpp:20
    #5 0x0001840244e0 in start+0x1b4c (dyld:arm64e+0x204e0)

0x60c000000ac0 is located 0 bytes inside of 128-byte region [0x60c000000ac0,0x60c000000b40)
freed by thread T0 here:
    #0 0x0001010d8f10 in free+0x74 (libclang_rt.asan_osx_dynamic.dylib:arm64+0x54f10)
    #1 0x0001009c0cd0 in process_data 05_double_free_conditional.c:12
    #2 0x0001009c0b14 in LLVMFuzzerTestOneInput SYN-05-DOUBLE-FREE.c:16
"""


def test_double_free_class_is_the_defect_not_the_verb():
    """
    ASan words this as "attempting double-free on 0x…". A bare word capture
    produced the class "attempting", which maps to no CWE and blurs clustering.
    """
    from src.analysis_engine.crash_triage import CrashTriage

    sig = CrashTriage.parse_sanitizer_report(_INLINED_DOUBLE_FREE)
    assert sig.crash_class == "double-free"
    assert sig.cwe_and_severity[0] == "CWE-415"


def test_libfuzzer_driver_frames_never_win_the_crash_location():
    """
    libFuzzer's entry point is a plain `main`, so a `fuzzer::` filter misses it.
    Without excluding its driver units the first non-noise frame of an inlined
    crash is `main FuzzerMain.cpp:20` and the bug is blamed on the fuzzer.
    """
    from pathlib import Path
    from src.analysis_engine.crash_triage import CrashTriage

    sig = CrashTriage.parse_sanitizer_report(
        _INLINED_DOUBLE_FREE, source_root=Path(__file__).parent.parent
    )
    assert "Fuzzer" not in sig.file_path
    assert sig.file_path.endswith("05_double_free_conditional.c")
    assert sig.line_number == 12


def test_target_frame_is_preferred_over_scaffolding_even_when_deeper():
    """
    The in-root frame must win regardless of position. Here the only target
    frame is in the secondary "freed by" stack, below several scaffolding
    frames — which is exactly what inlining produces.
    """
    from pathlib import Path
    from src.analysis_engine.crash_triage import CrashTriage

    root = Path(__file__).parent.parent
    with_root = CrashTriage.parse_sanitizer_report(_INLINED_DOUBLE_FREE, source_root=root)
    assert Path(with_root.file_path).exists(), (
        "resolved location must be a real file the orchestrator can open"
    )


def test_source_root_actually_filters():
    """
    The root check previously computed `relative_to` and discarded the result,
    so passing a source_root changed nothing. Here a third-party frame precedes
    the target frame and neither is scaffolding: only a working root check can
    tell them apart.
    """
    from pathlib import Path
    from src.analysis_engine.crash_triage import CrashTriage

    report = """\
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
    #0 0x1 in vendor_helper /opt/vendor/thirdparty.c:88
    #1 0x2 in process_data 05_double_free_conditional.c:12
"""
    root = Path(__file__).parent.parent

    with_root = CrashTriage.parse_sanitizer_report(report, source_root=root)
    assert with_root.file_path.endswith("05_double_free_conditional.c"), (
        "the frame under the source root must win over an earlier foreign frame"
    )

    without_root = CrashTriage.parse_sanitizer_report(report)
    assert without_root.file_path == "/opt/vendor/thirdparty.c", (
        "with no root to filter by, the first frame is all we can report"
    )


# ---------------------------------------------------------------------------
# LeakSanitizer availability
#
# This project recorded "LeakSanitizer is not supported on darwin-arm64" and
# left CWE-401 with no runtime gate on that basis. The blocker was the
# TOOLCHAIN, not the platform: Apple's ASan runtime answers detect_leaks=1 with
# "not supported on this platform", Homebrew LLVM's runtime does not.
# ---------------------------------------------------------------------------

def test_leak_pov_discriminates_the_weakness_not_the_binary(tmp_path):
    """
    The gate must fail on the leaking path and pass everywhere else — including
    on the ORIGINAL binary's benign path. A gate that simply fails on the
    unpatched binary would prove nothing about the leak.
    """
    import subprocess
    from pathlib import Path
    import pytest

    from tests.benchmarks.targets import _LSAN_CLANG, SAN_CFLAGS

    if not _LSAN_CLANG:
        pytest.skip("no LeakSanitizer-capable clang on this host")

    root = Path(__file__).parent.parent.parent
    original = root / "tests" / "demo_vulns" / "17_memory_leak_error_path.c"
    runner = root / "tests" / "benchmarks" / "harness" / "pov_leak.sh"

    fixed = tmp_path / "fixed.c"
    fixed.write_text(original.read_text().replace(
        "        return -1; ", "        free(log_msg);\n        return -1; ", 1))

    def build(src, out):
        cmd = f'"{_LSAN_CLANG}" {SAN_CFLAGS} "{src}" -o "{out}"'
        assert subprocess.run(cmd, shell=True, capture_output=True).returncode == 0

    orig_bin, fixed_bin = tmp_path / "orig", tmp_path / "fixed"
    build(original, orig_bin)
    build(fixed, fixed_bin)

    def gate(binary, arg):
        return subprocess.run(
            f'sh "{runner}" "{binary}" {arg}', shell=True, capture_output=True
        ).returncode

    assert gate(orig_bin, "-1") == 1, "the leak must reproduce on the original"
    assert gate(fixed_bin, "-1") == 0, "a patch that frees must clear the gate"
    assert gate(orig_bin, "10") == 0, (
        "the benign path leaks nothing even unpatched — otherwise the gate is "
        "detecting the binary rather than the weakness"
    )
    assert gate(fixed_bin, "10") == 0
