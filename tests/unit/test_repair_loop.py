"""
Unit tests for the repair-loop improvements: whole-function patching, the
Critic (LLM-as-judge), the deterministic escalation policy, and salient
failure-feedback extraction.

These encode the reasons each mechanism exists, so a regression shows up as a
failing expectation rather than a quietly worse benchmark score.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.agent_orchestrator.llm_client import LLMClient
from src.agent_orchestrator.critic import CriticFeedback, EscalationPolicy
from src.context_engine.tree_sitter_extractor import ContextExtractor
from src.patch_validator.drv_loop import DRVLoop


SAMPLE = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_and_null_terminate(const char* src, size_t size) {
    char* dest = (char*)malloc(size);
    for (size_t i = 0; i <= size; i++) {
        dest[i] = src[i];
    }
    free(dest);
}
int main(void) { return 0; }
"""


# --- whole-function replacement ------------------------------------------

def test_extracts_function_replacement():
    response = """Here is the corrected function.

```c
// FUNCTION: copy_and_null_terminate
void copy_and_null_terminate(const char* src, size_t size) {
    char* dest = (char*)malloc(size + 1);
    if (!dest) return;
    memcpy(dest, src, size);
    dest[size] = '\\0';
    free(dest);
}
```
"""
    result = LLMClient._extract_replacement(response)
    assert result is not None
    name, source = result
    assert name == "copy_and_null_terminate"
    assert "malloc(size + 1)" in source
    assert "// FUNCTION:" not in source, "marker line must be stripped"


def test_no_replacement_when_marker_absent():
    assert LLMClient._extract_replacement("```c\nint x = 1;\n```") is None


def test_replacement_requires_plausible_function_body():
    assert LLMClient._extract_replacement("```c\n// FUNCTION: foo\n```") is None


def test_find_function_span_and_replace(tmp_path):
    src = tmp_path / "t.c"
    src.write_text(SAMPLE)
    extractor = ContextExtractor()

    span = extractor.find_function_span(str(src), "copy_and_null_terminate")
    assert span is not None
    start, end = span
    assert SAMPLE[start:end].startswith("void copy_and_null_terminate")

    ok = extractor.replace_function(
        str(src), "copy_and_null_terminate",
        "void copy_and_null_terminate(const char* src, size_t size) { (void)src; (void)size; }",
    )
    assert ok
    body = src.read_text()
    assert "i <= size" not in body, "old body must be gone"
    assert "int main(void)" in body, "the rest of the file must survive"


def test_replace_unknown_function_leaves_file_untouched(tmp_path):
    src = tmp_path / "t.c"
    src.write_text(SAMPLE)
    assert ContextExtractor().replace_function(str(src), "no_such_function", "void x(){}") is False
    assert src.read_text() == SAMPLE


# --- salient feedback extraction -----------------------------------------

ASAN = """=================================================================
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000f4
WRITE of size 1 at 0x602000000f4 thread T0
    #0 0x102ab in copy_and_null_terminate 06_off_by_one_loop.c:10
0x602000000f4 is located 0 bytes after 4-byte region
allocated by thread T0 here:
SUMMARY: AddressSanitizer: heap-buffer-overflow 06_off_by_one_loop.c:10
Shadow bytes around the buggy address:
""" + "\n".join("  0x60200000%04x: 00 00 00 00 00 00 00 00" % i for i in range(200))


def test_salient_keeps_diagnosis_and_drops_shadow_dump():
    """Naive truncation keeps the banner and loses the SUMMARY — the useful part."""
    trimmed = DRVLoop._salient(ASAN, 600)
    assert len(trimmed) <= 700
    assert "ERROR: AddressSanitizer: heap-buffer-overflow" in trimmed
    assert "SUMMARY:" in trimmed
    assert "copy_and_null_terminate" in trimmed
    assert trimmed.count("00 00 00 00") < 5, "shadow-byte dump should be mostly gone"


def test_salient_passes_short_output_through():
    assert DRVLoop._salient("short error", 500) == "short error"


def test_salient_keeps_compiler_errors():
    out = "t.c:5:9: error: use of undeclared identifier 'sz'\n" + "noise\n" * 500
    assert "use of undeclared identifier" in DRVLoop._salient(out, 400)


# --- escalation policy (deterministic loop control) -----------------------

def test_pov_failure_always_triggers_critic():
    """A wrong fix is exactly the case raw sanitizer output has failed to convey."""
    assert EscalationPolicy().should_invoke_critic("pov") is True


def test_critic_held_back_until_repeated_failure_for_cheap_stages():
    policy = EscalationPolicy()
    assert policy.should_invoke_critic("apply") is False
    policy.record_failure("apply")
    policy.record_failure("apply")
    assert policy.should_invoke_critic("apply") is True


def test_repeated_apply_failures_force_the_replacement_format():
    policy = EscalationPolicy()
    assert not policy.should_force_replacement()
    policy.record_failure("apply")
    assert not policy.should_force_replacement()
    policy.record_failure("apply")
    assert policy.should_force_replacement(), "stop asking for diffs it cannot produce"


def test_loop_stops_early_when_stuck():
    """
    Stuck means resubmitting the SAME attempt, which is what the gist identifies.
    This test previously passed no gist and relied on a per-stage failure count,
    which also killed agents whose attempts were still changing.
    """
    policy = EscalationPolicy()
    for _ in range(3):
        policy.record_failure("pov", gist="the-same-wrong-fix")
    assert not policy.should_stop_early()
    policy.record_failure("pov", gist="the-same-wrong-fix")
    assert policy.should_stop_early(), "budget should not be spent repeating a failure"


def test_progress_does_not_trigger_early_stop():
    policy = EscalationPolicy()
    for stage in ("apply", "build", "pov", "regression"):
        policy.record_failure(stage, gist=f"fix-attempt-for-{stage}")
    assert not policy.should_stop_early(), "different stages mean the agent is progressing"


# --- critic verdict -------------------------------------------------------

def test_critic_feedback_renders_actionable_guidance():
    verdict = CriticFeedback(
        verdict="insufficient",
        root_cause="the loop writes dest[size] on a malloc(size) buffer",
        what_the_patch_missed="bounding the write removed the NUL terminator, so printf over-reads",
        instruction="allocate size + 1 bytes and write dest[size] = '\\0'",
    )
    text = verdict.as_guidance()
    assert "insufficient" in text
    assert "NUL terminator" in text
    assert "size + 1" in text


def test_critic_verdict_rejects_invalid_status():
    with pytest.raises(Exception):
        CriticFeedback(
            verdict="looks_fine",          # not in the allowed set
            root_cause="x", what_the_patch_missed="y", instruction="z",
        )
