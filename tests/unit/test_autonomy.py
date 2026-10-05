"""
Autonomous mode: ingest, code index, caller-derived preconditions, templates,
fairness. Pure-Python parts only; nothing here compiles or runs target code
(the build+fuzz stage is pending).
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.autonomy import ingest
from src.autonomy.codeindex import CodeIndex
from src.autonomy.harness import (
    HarnessUnavailable, Preconditions, fairness_violations, mine_preconditions,
    plan_slots, render_template, synthesize,
)
from src.patch_validator.drv_loop import DRVLoop

LIB_H = """#ifndef LIB_H
#define LIB_H
#include <stddef.h>
#define NAME_MAX_LEN 32
int parse_record(const unsigned char *buf, size_t len);
int set_mode(const char *name, int mode);
void format_name(char *out, size_t outlen, const char *in);
#endif
"""

LIB_C = """#include <string.h>
#include "lib.h"

static int decode_field(const unsigned char *p, size_t n) {
    return n > 2 ? p[2] : 0;
}

int parse_record(const unsigned char *buf, size_t len) {
    return decode_field(buf, len);
}

int set_mode(const char *name, int mode) {
    return (int)strlen(name) + mode;
}

void format_name(char *out, size_t outlen, const char *in) {
    strncpy(out, in, outlen);
}

static int unreachable_helper(int x) { return x; }
"""

APP_C = """#include "lib.h"
int main(void) {
    char name[NAME_MAX_LEN];
    format_name(name, sizeof(name), "x");
    set_mode("a", 1);
    set_mode("b", 4);
    return parse_record((const unsigned char *)"abc", 3);
}
"""


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "mylib"
    (r / "src").mkdir(parents=True)
    (r / "src" / "lib.h").write_text(LIB_H)
    (r / "src" / "lib.c").write_text(LIB_C)
    (r / "examples").mkdir()
    (r / "examples" / "app.c").write_text(APP_C)
    (r / ".git").mkdir()
    (r / ".git" / "config").write_text("ignored")
    return r


@pytest.fixture
def index(repo):
    return CodeIndex(repo, ["src/lib.c", "examples/app.c"])


def test_ingest_snapshot_census_and_plan(repo, tmp_path):
    snap = ingest.ingest(str(repo), tmp_path / "run")
    assert len(snap.sha256) == 64
    assert not (snap.root / ".git").exists()
    assert snap.census.c_files == 2 and snap.census.files_with_main == ["examples/app.c"]
    assert snap.plan.kind == "flat-c"
    assert snap.plan.library_sources == ["src/lib.c"]       # examples/ is not a fuzz target
    again = ingest.ingest(str(repo), tmp_path / "run2")
    assert again.sha256 == snap.sha256                       # content-addressed


def test_unknown_build_system_fails_loudly(repo, tmp_path):
    (repo / "meson.build").write_text("project('x', 'c')\n")
    with pytest.raises(ingest.IngestError, match="--build-cmd"):
        ingest.ingest(str(repo), tmp_path / "run")
    snap = ingest.ingest(str(repo), tmp_path / "run2", build_cmd="meson setup b")
    assert snap.plan.kind == "custom"


def test_cmake_and_make_detected(repo, tmp_path):
    (repo / "CMakeLists.txt").write_text("project(x C)\n")
    assert ingest.ingest(str(repo), tmp_path / "a").plan.kind == "cmake"
    (repo / "CMakeLists.txt").unlink()
    (repo / "Makefile").write_text("all:\n")
    assert ingest.ingest(str(repo), tmp_path / "b").plan.kind == "make"


def test_index_functions_and_calls(index):
    pr = index.function("parse_record")
    assert pr and not pr.is_static and [p.name for p in pr.params] == ["buf", "len"]
    assert pr.params[0].base == "unsigned char" and pr.params[0].pointer_depth == 1
    assert index.function("decode_field").is_static
    assert {s.caller for s in index.callers_of("set_mode")} == {"main"}
    assert index.header_declaring("parse_record") == "src/lib.h"


def test_preconditions_from_callers(index):
    pre = mine_preconditions(index, index.function("set_mode"))
    assert pre.literals == {1: ["1", "4"]}
    fmt = mine_preconditions(index, index.function("format_name"))
    assert fmt.buffer_size == {0: 32}            # NAME_MAX_LEN resolved from the header
    assert fmt.sizeof_of == {1: 0}


def test_template_buf_len_allocates_exact_size(index):
    fn = index.function("parse_record")
    slots = plan_slots(fn, mine_preconditions(index, fn))
    src = render_template(fn, slots, "src/lib.h")
    assert '#include "lib.h"' in src
    assert "malloc(n0 ? n0 : 1)" in src and "parse_record(" in src
    assert "LLVMFuzzerTestOneInput" in src


def test_template_uses_caller_literals(index):
    fn = index.function("set_mode")
    slots = plan_slots(fn, mine_preconditions(index, fn))
    src = render_template(fn, slots, None)
    assert "lits1[] = {1, 4}" in src


def test_template_output_buffer_is_caller_sized(index):
    fn = index.function("format_name")
    pre = mine_preconditions(index, fn)
    src = render_template(fn, plan_slots(fn, pre), None)
    assert "malloc(32)" in src
    assert fairness_violations(src, fn, pre) == []


def test_static_target_reached_through_caller(index):
    hs = synthesize(index, index.function("decode_field"))
    assert hs[0].method == "template"
    assert hs[0].call_path == ["parse_record", "decode_field"]


def test_static_with_no_external_caller_is_unavailable(index):
    with pytest.raises(HarnessUnavailable, match="static"):
        synthesize(index, index.function("unreachable_helper"))


def test_fairness_rejects_harness_that_never_calls_entry(index):
    fn = index.function("parse_record")
    src = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }"
    assert any("never calls" in p for p in fairness_violations(src, fn, Preconditions()))


def test_fairness_rejects_literal_callers_never_pass(index):
    fn = index.function("set_mode")
    pre = mine_preconditions(index, fn)
    src = ('int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) '
           '{ set_mode("x", 99); return 0; }')
    assert any("99" in p for p in fairness_violations(src, fn, pre))


def test_fairness_rejects_buffer_smaller_than_callers(index):
    fn = index.function("format_name")
    pre = mine_preconditions(index, fn)
    src = ('int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) '
           '{ char out[8]; format_name(out, 8, "abc"); return 0; }')
    assert any("8-byte buffer" in p for p in fairness_violations(src, fn, pre))


def test_runner_end_to_end_without_semgrep(repo, tmp_path, monkeypatch):
    """Ingest -> (stubbed) scan -> harness -> evidence.json with a reason per finding."""
    from src.analysis_engine import semgrep_runner
    from src.analysis_engine.semgrep_runner import SarifFinding
    from src.autonomy.runner import AutoRunner, NOT_EXECUTED_REASON

    class FakeSemgrep:
        def __init__(self, rules=""):
            pass

        def scan(self, target):
            return [SarifFinding("r1", "m", "error", str(Path(target) / "src/lib.c"), 5, 5),
                    SarifFinding("r2", "m", "error", str(Path(target) / "examples/app.c"), 4, 4)]

    monkeypatch.setattr(semgrep_runner, "SemgrepRunner", FakeSemgrep)
    res = AutoRunner(tmp_path / "run").run(str(repo))
    data = json.loads((tmp_path / "run" / "evidence.json").read_text())
    assert res.error == "" and data["summary"]["findings"] == 2
    lib, app = res.findings
    assert lib.function == "decode_field" and lib.status == "harness_ready"
    assert lib.reason == NOT_EXECUTED_REASON and (tmp_path / "run" / lib.harness).exists()
    assert app.status == "unproven" and "not the library" in app.reason
    assert all(f.reason for f in res.findings)          # nothing silent


def test_materialise_absolute_source_dir(tmp_path):
    src = tmp_path / "proj"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "x.c").write_text("int x;")
    (src / "y.h").write_text("")
    ws = tmp_path / "ws"
    ws.mkdir()
    out = DRVLoop._materialise(ws, str(src / "sub" / "x.c"), str(src))
    assert out == ws / "proj" / "sub" / "x.c" and out.exists()
    assert (ws / "proj" / "y.h").exists()
