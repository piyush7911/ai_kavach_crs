"""
Unit tests for AI Kavach CRS core modules.
"""

import os
import sys
import pytest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_llm_config, AGENT_PROMPTS
from src.context_engine.tree_sitter_extractor import ContextExtractor
from src.agent_orchestrator.llm_client import LLMClient


def test_config_loading():
    config = get_llm_config()
    assert "api_key" in config
    assert config["api_key"].startswith("sk-")
    assert "alpha" in config["models"]
    assert "beta" in config["models"]
    assert "gamma" in config["models"]


def test_tree_sitter_extraction():
    extractor = ContextExtractor()
    sample_file = "tests/samples/test_vulnerable.c"
    
    assert Path(sample_file).exists()
    
    # Line 11 is the strcpy() in process_user_input
    ctx = extractor.extract_context(sample_file, 11, language="c")
    
    assert ctx["function_name"] == "process_user_input"
    assert "strcpy" in ctx["function_code"]
    assert ctx["extraction_method"] == "tree-sitter"
    assert ctx["start_line"] > 0
    assert ctx["end_line"] >= ctx["start_line"]


def test_tree_sitter_names_pointer_returning_function():
    """`Node* create_node(int)` nests the declarator; the name must still resolve."""
    ctx = ContextExtractor().extract_context("tests/samples/test_vulnerable.c", 19, language="c")
    assert ctx["function_name"] == "create_node"
    assert ctx["extraction_method"] == "tree-sitter"


def test_tree_sitter_fallback():
    extractor = ContextExtractor()
    sample_file = "tests/samples/test_vulnerable.c"
    
    # Try line 1 (outside function, should trigger fallback or head context)
    ctx = extractor.extract_context(sample_file, 1, language="c")
    assert ctx is not None
    assert "full_context" in ctx


def test_llm_client_diff_extraction():
    raw_response = """
Here is the fix for the vulnerability:

```diff
--- a/test.c
+++ b/test.c
@@ -5,3 +5,3 @@
-strcpy(dest, src);
+strncpy(dest, src, sizeof(dest) - 1);
```
    """
    diff = LLMClient._extract_diff(raw_response)
    assert "strncpy" in diff
    assert "--- a/test.c" in diff


# --- DRV loop verification behaviour -------------------------------------
# These guard the properties that make the benchmark trustworthy: a gate must
# never be recorded as passing unless its command ran and exited 0.

from src.patch_validator.drv_loop import DRVLoop, GATE_PASS, GATE_FAIL, GATE_SKIPPED


def test_patch_line_counting_excludes_headers():
    diff = (
        "--- a/x.c\n+++ b/x.c\n@@ -1,3 +1,4 @@\n"
        " context\n-removed\n+added one\n+added two\n"
    )
    assert DRVLoop.count_patch_lines(diff) == 3


def test_content_fallback_applies_drifted_hunk(tmp_path):
    src = tmp_path / "x.c"
    src.write_text("int main(void) {\n    int i = 0;\n    return i;\n}\n")
    diff = (
        "--- a/x.c\n+++ b/x.c\n@@ -900,3 +900,3 @@\n"
        "     int i = 0;\n-    return i;\n+    return 0;\n"
    )
    ok, _ = DRVLoop._apply_patch(tmp_path, src, diff)
    assert ok
    assert "return 0;" in src.read_text()


def test_content_fallback_rejects_nonexistent_context(tmp_path):
    src = tmp_path / "x.c"
    original = "int main(void) { return 0; }\n"
    src.write_text(original)
    diff = (
        "--- a/x.c\n+++ b/x.c\n@@ -1,2 +1,2 @@\n"
        "     int totally_absent = 1;\n-    absent_call();\n+    fixed();\n"
    )
    ok, _ = DRVLoop._apply_patch(tmp_path, src, diff)
    assert not ok
    assert src.read_text() == original


def test_content_fallback_rejects_ambiguous_context(tmp_path):
    """The content-matching fallback must refuse a hunk it cannot place uniquely."""
    src = tmp_path / "x.c"
    original = "a();\nb();\na();\n"
    src.write_text(original)
    diff = "--- a/x.c\n+++ b/x.c\n@@ -1,1 +1,1 @@\n-a();\n+c();\n"
    ok, detail = DRVLoop._apply_by_content(src, diff)
    assert not ok
    assert "matched 2 locations" in detail
    assert src.read_text() == original


def test_unconfigured_gates_report_skipped_not_pass():
    """A gate with no command must never be recorded as a pass."""
    result = DRVLoop.run.__globals__["PatchResult"](
        iteration=1, agent_name="beta", patch_diff="x"
    )
    assert result.pov_ok == GATE_SKIPPED
    assert result.regression_ok == GATE_SKIPPED
    assert result.executed_gates == []


def test_expand_leaves_unknown_braces_untouched():
    out = DRVLoop.expand('gcc "{src}" -o "{bin}" && echo ${x[1]}', {"src": "/a.c", "bin": "/b"})
    assert '"/a.c"' in out and '"/b"' in out and "${x[1]}" in out


def test_preflight_handles_commands_containing_literal_braces():
    """
    Regression: preflight used str.format(**ctx), which raises KeyError on any
    command containing literal braces — JSON payloads, shell brace expansion,
    awk programs. The real-CVE target's regression command asserts on the output
    `{"a":1}` and crashed the whole pre-flight before this was fixed.
    """
    from src.patch_validator.drv_loop import DRVLoop
    ctx = {"src": "/tmp/a.c", "srcdir": "/tmp", "bin": "/tmp/b", "workspace": "/tmp/w"}
    cmd = 'sh run.sh "{bin}" "minified: {\\"a\\":1}" \'{ "a" : 1 }\''
    out = DRVLoop.expand(cmd, ctx)
    assert "/tmp/b" in out                       # placeholder substituted
    assert '{ "a" : 1 }' in out                  # literal JSON preserved
    assert '{\\"a\\":1}' in out


def test_preflight_uses_the_brace_safe_expander():
    """Guard against reintroducing raw .format(**ctx) in the pre-flight path."""
    import pathlib
    src = pathlib.Path(__file__).parent.parent.parent / "benchmark.py"
    assert ".format(**ctx)" not in src.read_text(), (
        "benchmark.py must expand command templates with DRVLoop.expand; "
        "str.format crashes on literal braces"
    )
