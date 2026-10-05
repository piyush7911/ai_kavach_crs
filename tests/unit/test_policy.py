"""Patch policy gate: one test per rule, plus the honest fix passing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.patch_validator.policy import PatchPolicy, changed_paths, snapshot

ORIGINAL = """#include <stdlib.h>
#include <string.h>

static int helper(int x) {
    return x + 1;
}

void copy_it(const char *src, size_t size) {
    char *dest = malloc(64);
    if (!dest) return;
    for (size_t i = 0; i < size; i++) dest[i] = src[i];
    free(dest);
}
"""
FLAGGED = 11


def rules(patched, **kw):
    r = PatchPolicy().check(ORIGINAL, patched, target_rel="t.c", flagged_line=FLAGGED, **kw)
    return {v.rule for v in r.violations}, r


def test_honest_fix_passes():
    patched = ORIGINAL.replace("malloc(64)", "malloc(size + 1)")
    found, r = rules(patched)
    assert found == set()
    assert r.function == "copy_it"
    assert r.changed_lines == 2


def test_added_include_is_allowed():
    patched = "#include <stdint.h>\n" + ORIGINAL.replace("malloc(64)", "malloc(size + 1)")
    assert rules(patched)[0] == set()


def test_edit_outside_flagged_function():
    patched = ORIGINAL.replace("return x + 1;", "return x + 2;")
    assert "in_flagged_function" in rules(patched)[0]


def test_changed_line_cap():
    body = "\n".join(f"    (void)size; /* {i} */" for i in range(100))
    patched = ORIGINAL.replace("    free(dest);", body + "\n    free(dest);")
    assert "changed_line_cap" in rules(patched)[0]


def test_signal_handler_denied():
    patched = ORIGINAL.replace("    if (!dest) return;", "    signal(11, 0);\n    if (!dest) return;")
    found, r = rules(patched)
    assert "denied_construct" in found
    assert "signal_handler" in str(r.violations)


def test_no_sanitize_denied():
    patched = ORIGINAL.replace("void copy_it(", '__attribute__((no_sanitize("address"))) void copy_it(')
    assert "denied_construct" in rules(patched)[0]


def test_inline_asm_denied():
    patched = ORIGINAL.replace("    free(dest);", '    __asm__ volatile("" ::: "memory");\n    free(dest);')
    assert "denied_construct" in rules(patched)[0]


def test_exit_and_getenv_denied():
    for line in ("    if (size > 64) exit(0);", '    if (getenv("X")) return;',
                 "    longjmp(env, 1);"):
        patched = ORIGINAL.replace("    if (!dest) return;", line + "\n    if (!dest) return;")
        assert "denied_construct" in rules(patched)[0], line


def test_denied_word_in_comment_or_string_is_ignored():
    patched = ORIGINAL.replace("    free(dest);", '    /* do not exit(0) here */\n    free(dest);')
    assert "denied_construct" not in rules(patched)[0]


def test_other_file_and_test_file():
    patched = ORIGINAL.replace("malloc(64)", "malloc(size + 1)")
    found, _ = rules(patched, workspace_changes=["t.c", "other.c", "tests/run.sh", "Makefile"])
    assert {"single_file", "no_test_or_build_edit"} <= found


def test_workspace_snapshot_detects_change(tmp_path):
    (tmp_path / "a.c").write_text("x")
    (tmp_path / "b.sh").write_text("y")
    before = snapshot(tmp_path)
    (tmp_path / "b.sh").write_text("z")
    assert changed_paths(before, snapshot(tmp_path)) == ["b.sh"]
