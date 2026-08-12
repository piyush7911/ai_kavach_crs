"""
Tests for agent memory.

The properties guarded here are the ones the memory literature identifies as
the failure modes that make agent memory dangerous: self-reinforcing error,
stale patterns retaining influence, retrieval noise, and unbounded growth.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.memory import (
    MemorySystem, WorkingMemory, SemanticMemory, ProceduralMemory, FixPattern,
)


@pytest.fixture
def store(tmp_path):
    return tmp_path / "mem"


# --- working memory --------------------------------------------------------

def test_ledger_lists_rejected_attempts():
    """
    Observed failure: agents oscillated between two rejected fixes because each
    iteration only saw the latest rejection. The ledger shows all of them.
    """
    w = WorkingMemory("SYN-06")
    w.record(1, "beta", "--- a\n+++ b\n+    if (i < size) {", "pov", "insufficient")
    w.record(2, "beta", "--- a\n+++ b\n+    dest[size] = 0;", "regression", "regression_risk")

    rendered = w.render()
    assert "if (i < size)" in rendered
    assert "dest[size] = 0;" in rendered
    assert "pov" in rendered and "regression" in rendered
    assert "must be materially different" in rendered


def test_ledger_detects_a_repeated_patch():
    w = WorkingMemory("X")
    w.record(1, "beta", "+    if (n > 64) return;", "pov")
    assert w.has_tried("+    if (n > 64) return;")
    assert not w.has_tried("+    if (n > 128) return;")


def test_empty_ledger_renders_nothing():
    assert WorkingMemory("X").render() == ""


def test_ledger_is_bounded():
    """Unbounded ledgers dilute attention; only the recent tail is rendered."""
    w = WorkingMemory("X")
    for i in range(30):
        w.record(i, "beta", f"+    attempt_{i}();", "pov")
    assert w.render().count("attempt_") <= WorkingMemory.MAX_RENDERED


# --- semantic memory -------------------------------------------------------

def _pattern(**kw):
    base = dict(
        cwe="CWE-193", crash_class="heap-buffer-overflow",
        root_cause="loop writes dest[size] on a malloc(size) buffer",
        fix_strategy="allocate size + 1 bytes and terminate at dest[size]",
        source_target="SYN-06",
    )
    base.update(kw)
    return FixPattern(**base)


def test_recall_matches_on_cwe_and_crash_class(store):
    m = SemanticMemory(store)
    m.remember(_pattern())
    m.remember(_pattern(cwe="CWE-416", crash_class="heap-use-after-free",
                        root_cause="pointer used after free",
                        fix_strategy="null the pointer after free",
                        source_target="JULIET-CWE416"))

    hits = m.recall("CWE-193", "heap-buffer-overflow", "off by one loop")
    assert hits and hits[0].cwe == "CWE-193"


def test_recall_is_capped_to_avoid_attentional_dilution(store):
    m = SemanticMemory(store)
    for i in range(10):
        m.remember(_pattern(source_target=f"T{i}", fix_strategy=f"strategy variant {i} bounds check"))
    assert len(m.recall("CWE-193", "heap-buffer-overflow", "overflow", limit=2)) <= 2


def test_unrelated_bug_class_is_not_recalled(store):
    m = SemanticMemory(store)
    m.remember(_pattern())
    assert m.recall("CWE-798", "", "hardcoded credentials in source") == []


def test_duplicate_patterns_are_merged_not_duplicated(store):
    m = SemanticMemory(store)
    assert m.remember(_pattern(pitfalls=["a"]))
    assert not m.remember(_pattern(pitfalls=["b"])), "near-identical pattern must merge"
    assert len(m.patterns) == 1
    assert set(m.patterns[0].pitfalls) == {"a", "b"}


def test_memory_persists_across_instances(store):
    SemanticMemory(store).remember(_pattern())
    assert len(SemanticMemory(store).patterns) == 1


def test_hardened_patterns_outrank_unhardened():
    assert _pattern(hardened=True).confidence > _pattern(hardened=False).confidence


def test_confidence_decays_when_a_pattern_misleads(store):
    """
    Guard against self-reinforcing error: a pattern that keeps being recalled
    and keeps failing must lose influence rather than mislead forever.
    """
    m = SemanticMemory(store)
    m.remember(_pattern(hardened=True))
    before = m.patterns[0].confidence

    recalled = m.recall("CWE-193", "heap-buffer-overflow", "off by one")
    for _ in range(4):
        m.record_outcome(recalled, succeeded=False)

    assert m.patterns[0].confidence < before


def test_confidence_rises_when_a_pattern_helps(store):
    m = SemanticMemory(store)
    m.remember(_pattern(hardened=False))
    recalled = m.recall("CWE-193", "heap-buffer-overflow", "off by one")
    for _ in range(4):
        m.record_outcome(recalled, succeeded=True)
    assert m.patterns[0].confidence > _pattern(hardened=False).confidence


def test_empty_strategy_is_not_stored(store):
    """Write-path filtering: storing noise verbatim poisons the store."""
    assert not SemanticMemory(store).remember(_pattern(fix_strategy="   "))


def test_prompt_rendering_marks_memory_as_evidence_not_instruction(store):
    m = SemanticMemory(store)
    m.remember(_pattern())
    text = m.render_for_prompt(m.recall("CWE-193", "heap-buffer-overflow", "off by one"))
    assert "evidence, not instructions" in text


# --- procedural memory -----------------------------------------------------

def test_agent_order_follows_demonstrated_wins(store):
    p = ProceduralMemory(store)
    for _ in range(3):
        p.record("CWE-193", "gamma", 2, True)
    p.record("CWE-193", "alpha", 4, True)

    order = p.preferred_agent_order("CWE-193", ["alpha", "beta", "gamma"])
    assert order[0] == "gamma", "the agent that actually wins should go first"


def test_agent_order_unchanged_without_evidence(store):
    default = ["alpha", "beta", "gamma"]
    assert ProceduralMemory(store).preferred_agent_order("CWE-999", default) == default


def test_iteration_budget_adapts_to_observed_difficulty(store):
    p = ProceduralMemory(store)
    for _ in range(5):
        p.record("CWE-121", "beta", 2, True)      # consistently easy
    assert p.suggested_iterations("CWE-121", 8) < 8


def test_iteration_budget_needs_evidence(store):
    assert ProceduralMemory(store).suggested_iterations("CWE-000", 8) == 8


# --- system-level ----------------------------------------------------------

def test_only_validated_fixes_are_learned(store):
    """
    The central safety property: memory records verified outcomes, so a fix is
    stored because gates proved it, not because an agent claimed it.
    """
    m = MemorySystem(store)
    assert m.learn_from(
        target_id="SYN-06", cwe="CWE-193", crash_class="heap-buffer-overflow",
        root_cause="off-by-one write", fix_strategy="allocate size + 1",
        pitfalls=["bounding the loop alone drops the terminator"],
        winning_agent="alpha", iterations=3, hardened=True,
    )
    stats = m.stats()
    assert stats["semantic_patterns"] == 1
    assert stats["hardened_patterns"] == 1


def test_disabled_memory_neither_recalls_nor_learns(store):
    m = MemorySystem(store, enabled=False)
    assert m.recall_for("CWE-193", "heap-buffer-overflow", "x") == []
    assert not m.learn_from("T", "CWE-193", "c", "r", "f", [], "alpha", 1, True)


def test_episodes_are_appended(store):
    m = MemorySystem(store)
    m.episodic.record({"vulnerability_id": "A", "status": "patched"})
    m.episodic.record({"vulnerability_id": "B", "status": "unresolved"})
    assert [e["vulnerability_id"] for e in m.episodic.all()] == ["A", "B"]


# ---------------------------------------------------------------------------
# Attempt identity — these pin the two defects that made a hard real CVE
# (CVE-2019-11834) pass or fail depending on the run.
# ---------------------------------------------------------------------------

_REPL_A = """static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)
{
    const unsigned char *input_end = buffer_at_offset(input_buffer) + 1;
    while ((*input_end != '"') && (offset < input_buffer->length))
    {
        input_end++;
    }
}"""

# The real fix: the two conditions swapped. Shares signature, opening brace and
# first statement with the attempt above — i.e. everything the old gist looked at.
_REPL_B = _REPL_A.replace(
    "while ((*input_end != '\"') && (offset < input_buffer->length))",
    "while ((offset < input_buffer->length) && (*input_end != '\"'))",
)


def test_whole_function_replacements_are_distinguishable():
    """
    A whole-function replacement has no '+' lines. The gist used to fall back to
    the first three non-empty lines, which for a replacement are the signature
    and the opening brace — identical across every attempt at the same function.
    Two materially different fixes were therefore judged to be the same attempt.
    """
    from src.memory.store import WorkingMemory

    assert WorkingMemory.summarise_patch(_REPL_A) != WorkingMemory.summarise_patch(_REPL_B)


def test_has_tried_does_not_false_positive_on_replacements():
    from src.memory.store import WorkingMemory

    mem = WorkingMemory("T")
    mem.record(iteration=1, agent="alpha", patch=_REPL_A, rejected_by="pov")
    assert mem.has_tried(_REPL_A)
    assert not mem.has_tried(_REPL_B), "the corrected fix was mistaken for an attempt already refused"


def test_reformatting_alone_is_still_the_same_attempt():
    """Identity must survive whitespace, or the loop never detects a real stall."""
    from src.memory.store import WorkingMemory

    reflowed = _REPL_A.replace("    ", "        ").replace("\n", "\n")
    assert WorkingMemory.summarise_patch(_REPL_A) == WorkingMemory.summarise_patch(reflowed)


def test_diff_format_still_summarised_by_added_lines():
    from src.memory.store import WorkingMemory

    diff = "--- a/x.c\n+++ b/x.c\n@@\n-    bad();\n+    good(n);\n"
    assert "good(n)" in WorkingMemory.summarise_patch(diff)


def test_distinct_attempts_do_not_trigger_early_stop():
    """
    The counter is named GIVE_UP_AFTER_IDENTICAL_FAILURES but used to count
    failures per *stage*. An agent that reached the PoV gate four times with
    four different candidate fixes was killed as though it were looping — which
    is what made a solvable target fail on some runs and pass on others.
    """
    from src.agent_orchestrator.critic import EscalationPolicy

    policy = EscalationPolicy()
    for i in range(6):
        policy.record_failure("pov", gist=f"attempt-{i}")
    assert not policy.should_stop_early(), "gave up while attempts were still changing"


def test_identical_attempts_do_trigger_early_stop():
    from src.agent_orchestrator.critic import EscalationPolicy

    policy = EscalationPolicy()
    for _ in range(EscalationPolicy.GIVE_UP_AFTER_IDENTICAL_FAILURES):
        policy.record_failure("pov", gist="same-every-time")
    assert policy.should_stop_early(), "failed to notice a genuine stall"


def test_stall_detection_needs_a_consecutive_run():
    """A repeat early on must not count once the agent has moved on."""
    from src.agent_orchestrator.critic import EscalationPolicy

    policy = EscalationPolicy()
    for gist in ("a", "a", "a", "b"):
        policy.record_failure("pov", gist=gist)
    assert not policy.should_stop_early()
