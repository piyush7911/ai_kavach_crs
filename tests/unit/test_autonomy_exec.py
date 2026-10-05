"""
Autonomous mode, execution stages: build, fuzz, replay oracle. These compile and
run a tiny fixture under the sandbox, so they need a libFuzzer-capable clang and
are skipped (not passed) without one.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.autonomy import build, campaign, execute
from src.autonomy.repair import variants_of
from src.patch_validator import sandbox

try:
    CLANG = build.fuzz_clang()
except build.BuildError:
    CLANG = None
pytestmark = pytest.mark.skipif(CLANG is None, reason="no libFuzzer-capable clang")

LIB = """#include <stdio.h>
#include <string.h>
#include <stddef.h>
int parse(const unsigned char *b, size_t n) {
    char buf[8];
    if (n > 0 && b[0] == 'X') { memcpy(buf, b, n); return buf[0]; }   /* overflow when n > 8 */
    printf("ok %zu\\n", n);
    return (int)n;
}
"""
HARNESS = """#include <stddef.h>
#include <stdint.h>
int parse(const unsigned char *b, size_t n);
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { parse(d, n); return 0; }
"""


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    execute.default_to_required()
    root = tmp_path_factory.mktemp("repo")
    (root / "lib.c").write_text(LIB)
    work = tmp_path_factory.mktemp("work")
    h = work / "h.c"
    h.write_text(HARNESS)
    script = build.write_script(work / "b.sh", build.render_script(
        clang=CLANG, sources=["lib.c"], include_dirs=[], defines=[], harness=h, target_file="lib.c"))
    out = build.build(script, root, work / "bin" / "orig", work)
    if not out.ok and "sandbox" in (out.note + out.error).lower():
        pytest.skip("sandbox unavailable: " + out.error[:100])
    assert out.ok, out.error
    return root, work, script, out.binary


def test_fuzzer_finds_the_overflow(built):
    root, work, script, binary = built
    seeds = work / "seeds"
    campaign.write_seeds(seeds, [b"hello", b"Xab"])
    fz = campaign.fuzz(binary, work, 10, seeds)
    assert fz.ran and fz.crashes


def test_original_passes_its_own_replay_check(built):
    """The oracle must accept the unpatched binary, or it rejects every correct patch."""
    root, work, script, binary = built
    seeds = work / "seeds2"
    campaign.write_seeds(seeds, [b"hello", b"", b"abc\n", b"Xab"])
    golden = campaign.capture_golden(binary, sorted(seeds.glob("*")), work)
    assert golden, "the original handled no input cleanly"
    gpath = campaign.write_golden(golden, work / "golden.tsv")
    check = campaign.write_replay_check(work / "check.sh")
    r = execute.run(f'sh {check} {binary} {gpath}', work)
    assert r.ok, r.output


def test_replay_check_rejects_changed_behaviour(built):
    root, work, script, binary = built
    seeds = work / "seeds3"
    campaign.write_seeds(seeds, [b"hello"])
    golden = campaign.capture_golden(binary, sorted(seeds.glob("*")), work)
    golden[0].stdout_sha1 = "0" * 40
    gpath = campaign.write_golden(golden, work / "bad.tsv")
    check = campaign.write_replay_check(work / "check2.sh")
    assert not execute.run(f'sh {check} {binary} {gpath}', work).ok


def test_build_refuses_output_outside_workspace(built, tmp_path):
    root, work, script, binary = built
    with pytest.raises(ValueError):
        build.build(script, root, tmp_path / "x", work)


def test_variants_are_distinct_and_exclude_original():
    v = variants_of(b"Xabcdefghij")
    assert v and b"Xabcdefghij" not in v and len(v) == len(set(v))


def test_model_harness_receives_a_nul_terminated_copy(tmp_path):
    """A drafted harness that treats the input as a C string must not over-read it."""
    from src.autonomy.runner import with_prelude
    execute.default_to_required()
    src = with_prelude('int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) '
                       '{ return (int)strlen((const char *)d) > 3; }', terminate=True)
    h = tmp_path / "h.c"
    h.write_text(src)
    script = build.write_script(tmp_path / "b.sh", build.render_script(
        clang=CLANG, sources=["x.c"], include_dirs=[], defines=[], harness=h, target_file="x.c"))
    root = tmp_path / "r"
    root.mkdir()
    (root / "x.c").write_text("int unused_symbol;")
    out = build.build(script, root, tmp_path / "bin" / "o", tmp_path)
    assert out.ok, out.error
    inp = tmp_path / "in"
    inp.write_bytes(b"abcd")                  # exactly sized: a bare strlen(data) would over-read
    r = campaign.replay(out.binary, inp, tmp_path, trace=False)
    assert "AddressSanitizer" not in r.output, r.output[:300]


# -- hardening retry (stubbed repair step: deterministic, no compiler or model) ----------------

def _fake_once(statuses, seen):
    from src.autonomy.repair import RepairOutcome

    it = iter(statuses)

    def once(**kw):
        seen.append(kw["vuln"].description)
        st = next(it)
        return RepairOutcome(status=st, reason="r", cost_usd=0.5, seconds=1.0, diff=f"d-{st}",
                             hardening={"detail": "OOM: a leak"} if st == "falsified" else {})
    return once


def _stub_helpers(R, monkeypatch):
    monkeypatch.setattr(R, "explain_crash", lambda v, c: "")
    monkeypatch.setattr(R, "expand_pov_inputs", lambda b, ins, w, v: list(ins))


_ARGS = dict(crash_input=Path("c"), original_bin=Path("o"), work=Path("."))


def _vuln():
    from src.agent_orchestrator.orchestrator import VulnerabilityReport
    return VulnerabilityReport(id="V", source="fuzzer", file_path="f.c", line_number=1, description="bug")


def test_falsified_patch_is_retried_with_the_reason(monkeypatch):
    from src.autonomy import repair as R
    seen = []
    _stub_helpers(R, monkeypatch)
    monkeypatch.setattr(R, "_repair_once", _fake_once(["falsified", "proven"], seen))
    out = R.repair(**_ARGS, vuln=_vuln())
    assert out.status == "proven" and len(seen) == 2
    assert "OOM: a leak" in seen[1] and "OOM" not in seen[0]
    assert out.previous_attempts and out.previous_attempts[0]["status"] == "falsified"   # never hidden
    assert out.cost_usd == 1.0                                                           # both attempts paid for


def test_retries_are_bounded_and_failure_is_reported(monkeypatch):
    from src.autonomy import repair as R
    seen = []
    _stub_helpers(R, monkeypatch)
    monkeypatch.setattr(R, "_repair_once", _fake_once(["falsified", "falsified", "proven"], seen))
    out = R.repair(**_ARGS, vuln=_vuln(), hardening_retries=1)
    assert out.status == "falsified" and len(seen) == 2


def test_no_retry_when_first_attempt_is_proven_or_retries_off(monkeypatch):
    from src.autonomy import repair as R
    seen = []
    _stub_helpers(R, monkeypatch)
    monkeypatch.setattr(R, "_repair_once", _fake_once(["proven"], seen))
    assert R.repair(**_ARGS, vuln=_vuln()).previous_attempts == [] and len(seen) == 1
    seen.clear()
    _stub_helpers(R, monkeypatch)
    monkeypatch.setattr(R, "_repair_once", _fake_once(["falsified"], seen))
    assert R.repair(**_ARGS, vuln=_vuln(), hardening_retries=0).status == "falsified" and len(seen) == 1


# -- a hanging patched binary must fail fast, not hold a gate for minutes ----------------------

def _hang_binary(tmp_path):
    import subprocess
    src = tmp_path / "hang.c"
    # Ignore SIGALRM, as libFuzzer/ASan binaries effectively do: an alarm-only timeout never fires.
    src.write_text("#include <signal.h>\nint main(void){ signal(SIGALRM, SIG_IGN); for(;;); }")
    out = tmp_path / "hang"
    subprocess.run(["cc", str(src), "-o", str(out)], check=True)
    return out


def test_pov_runner_times_out_a_hanging_binary(tmp_path):
    import os, subprocess, time
    hang = _hang_binary(tmp_path)
    runner = Path(__file__).resolve().parents[2] / "tests" / "benchmarks" / "harness" / "pov_run.sh"
    t = time.time()
    r = subprocess.run(["sh", str(runner), str(hang)], capture_output=True, text=True,
                       env={**os.environ, "KAVACH_POV_TIMEOUT": "2"}, timeout=30)
    assert r.returncode == 1 and "TIMEOUT" in r.stdout
    assert time.time() - t < 10


def test_replay_check_fails_fast_on_a_hang(tmp_path):
    import subprocess, time
    hang = _hang_binary(tmp_path)
    inp = tmp_path / "in"
    inp.write_bytes(b"x")
    gold = tmp_path / "g.tsv"
    gold.write_text(f"0000\t0\t{inp}\n")
    check = campaign.write_replay_check(tmp_path / "c.sh")
    t = time.time()
    r = subprocess.run(["sh", str(check), str(hang), str(gold)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and "hang" in r.stdout
    assert time.time() - t < 30


def test_pov_runner_still_reports_exit_codes_and_clean_runs(tmp_path):
    import os, subprocess
    runner = Path(__file__).resolve().parents[2] / "tests" / "benchmarks" / "harness" / "pov_run.sh"
    ok = tmp_path / "ok.c"; ok.write_text("int main(void){return 0;}")
    sig = tmp_path / "sig.c"; sig.write_text("#include <stdlib.h>\nint main(void){abort();}")
    for src in (ok, sig):
        subprocess.run(["cc", str(src), "-o", str(src.with_suffix(""))], check=True)
    assert subprocess.run(["sh", str(runner), str(ok.with_suffix(""))], capture_output=True).returncode == 0
    r = subprocess.run(["sh", str(runner), str(sig.with_suffix(""))], capture_output=True, text=True)
    assert r.returncode == 1 and "died on signal" in r.stdout and "TIMEOUT" not in r.stdout


def test_pov_gate_replays_every_input_in_the_cluster(tmp_path):
    from src.autonomy.repair import gate_commands
    a, b, c = (tmp_path / n for n in ("crash-a", "crash-b", "crash-c"))
    for p in (a, b, c):
        p.write_bytes(b"x")
    _, pov, _ = gate_commands(tmp_path / "s.sh", "snap", a, None, None, crash_inputs=[a, b, c, b])
    assert pov.count("pov_run.sh") == 3                       # a, b, c once each, no duplicates
    assert all(str(p) in pov for p in (a, b, c)) and pov.count("|| exit 1") == 3


# -- root-cause brief and PoV expansion --------------------------------------------------------

def test_explain_crash_states_the_access_line_and_trigger(tmp_path):
    from src.autonomy.repair import explain_crash
    src = tmp_path / "lib.c"
    src.write_text("\n".join(f"line{i}" for i in range(1, 21)))
    crash = tmp_path / "crash-1"
    crash.write_bytes(b"/*abc")
    vuln = _vuln()
    vuln.file_path, vuln.line_number = str(src), 10
    vuln.crash_trace = ("ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 1 at 0x6020\n"
                        "0x6020 is located 0 bytes after 6-byte region [0x6010,0x6020)\n")
    text = explain_crash(vuln, crash)
    assert "READ of 1 byte" in text and "past the end of a 6-byte allocation" in text
    assert ">> line10" in text and "b'/*abc'" in text
    assert "Do not delete or rewrite comments" in text


def test_pov_inputs_expand_to_variants_that_crash_the_same_line(built):
    from src.autonomy.repair import expand_pov_inputs
    root, work, script, binary = built
    crash = work / "crash-seed"
    crash.write_bytes(b"XXXXXXXXXXXX")                     # 12 bytes starting with X: overflows
    vuln = _vuln()
    vuln.file_path, vuln.line_number = str(root / "lib.c"), 6
    out = expand_pov_inputs(binary, [crash], work, vuln)
    assert out[0] == crash and len(out) > 1               # variants that also overflow at line 6
    assert all(p.read_bytes()[:1] == b"X" for p in out)   # the ones that don't start with X are clean


def _binary_from(tmp_path, name, body):
    work = tmp_path / name
    work.mkdir()
    (work / "r").mkdir()
    (work / "r" / "lib.c").write_text(body)
    h = work / "h.c"
    h.write_text(HARNESS)
    sc = build.write_script(work / "b.sh", build.render_script(
        clang=CLANG, sources=["lib.c"], include_dirs=[], defines=[], harness=h, target_file="lib.c"))
    out = build.build(sc, work / "r", work / "bin" / "x", work)
    assert out.ok, out.error
    return sc, work / "r", out.binary, work


def test_preexisting_second_bug_is_reported_not_blamed_on_the_patch(tmp_path):
    """
    The original has TWO bugs (an 'X' overflow and a 'Y' overflow). The patch fixes only 'X'.
    Re-fuzzing finds the 'Y' crash, which the original has too: it must be listed as a
    separate bug, and the patch must NOT be marked falsified for it.
    """
    from src.autonomy.repair import harden
    two_bugs = LIB.replace("    printf", "    if (n > 0 && b[0] == 'Y') { memcpy(buf, b, n); return buf[0]; }\n    printf")
    fixed_x = two_bugs.replace("if (n > 0 && b[0] == 'X') { memcpy(buf, b, n);",
                               "if (n > 0 && b[0] == 'X') { memcpy(buf, b, n > 8 ? 8 : n);")
    script, _, orig_bin, work = _binary_from(tmp_path, "orig", two_bugs)
    _, patched_root, _, _ = _binary_from(tmp_path, "pat", fixed_x)
    seeds = work / "seeds"
    campaign.write_seeds(seeds, [b"hello", b"Xab", b"Yab"])
    crash = work / "crash-x"
    crash.write_bytes(b"XXXXXXXXXXXX")
    v = harden(script=script, original_bin=orig_bin, patched_root=patched_root, work=work, seed_dir=seeds,
               corpus_dir=work / "corpus", crash_input=crash, refuzz_seconds=15)
    assert v.overfitting_checked
    assert v.additional_bugs, "the second, pre-existing bug should have been found and listed"
    assert not v.overfitted and not v.falsified
