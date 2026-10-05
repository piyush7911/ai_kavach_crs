"""
Adaptive repair strategy: spend model calls in proportion to how hard the bug is.

The repair loop is stubbed with scripted outcomes, so these tests are deterministic and
need neither a model nor a compiler. What they pin down:

  * an easy bug costs one agent run, not three;
  * a failed tier hands what it tried (and why it failed) to the next tier;
  * only the last tier fans out in parallel, and only it uses the stronger model;
  * without a stronger model configured, nothing pretends to use one;
  * explicit `agents=[...]` still runs the old ensemble paths unchanged.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from src.agent_orchestrator.orchestrator import Orchestrator, VulnerabilityReport
from src.memory.store import Attempt
from src.patch_validator.drv_loop import DRVReport, PatchResult


class FakeLLM:
    def __init__(self, escalate_model=""):
        self.usage_log = []
        self.escalate_model = escalate_model
        self.models = {"alpha": "base", "beta": "base", "gamma": "base"}

    def get_usage_summary(self):
        return {"estimated_cost_usd": 0.0}


class FakeDRV:
    """Records every run() and answers from a script of (success, patch_lines) per call."""

    def __init__(self, llm, script):
        self.llm = llm
        self.script = list(script)
        self.calls = []

    def run(self, **kw):
        self.calls.append(kw)
        success, lines = self.script.pop(0)
        self.llm.usage_log.append({"agent": kw["agent_name"]})        # one model call per run
        rep = DRVReport(agent_name=kw["agent_name"], vulnerability_id=kw["vulnerability_id"],
                        total_iterations=1, max_iterations=kw["max_iterations"], success=success,
                        winning_patch="patch" if success else None)
        it = PatchResult(iteration=1, agent_name=kw["agent_name"], patch_diff="patch")
        it.patch_line_count = lines
        it.fully_validated = success
        if not success:
            it.error_feedback = f"rejected output from {kw['agent_name']}"
            it.failure_stage = "pov"
            rep.attempt_ledger = [Attempt(iteration=1, agent=kw["agent_name"],
                                          summary=f"{kw['agent_name']}-tried-X", rejected_by="pov")]
        rep.iterations.append(it)
        return rep


def _vuln():
    return VulnerabilityReport(id="V", source="t", file_path="x.c", line_number=1,
                               description="d", cwe_id="CWE-125")


def _orch(script, escalate=""):
    llm = FakeLLM(escalate)
    o = Orchestrator(llm_client=llm, strategy="adaptive")
    o.drv_loop = FakeDRV(llm, script)
    return o


def test_an_easy_bug_costs_one_agent_run():
    o = _orch([(True, 5)])
    r = o.process_vulnerability(_vuln())
    assert r.status == "patched" and r.winning_agent == "alpha"
    assert len(o.drv_loop.calls) == 1 and r.tiers_used == 1 and r.llm_calls == 1


def test_a_failed_tier_hands_its_attempts_to_the_next():
    o = _orch([(False, 5), (True, 3)])
    r = o.process_vulnerability(_vuln())
    assert r.status == "patched" and r.winning_agent == "beta" and r.tiers_used == 2
    first, second = o.drv_loop.calls
    assert "PRIOR ATTEMPTS" not in first["vulnerability_context"]
    assert "PRIOR ATTEMPTS" in second["vulnerability_context"]
    assert "alpha-tried-X" in second["vulnerability_context"] and "rejected output from alpha" in \
        second["vulnerability_context"]
    assert second["agent_name"] == "beta"


def test_only_the_last_tier_uses_the_strong_model_and_names_are_kept():
    o = _orch([(False, 5), (False, 5), (False, 5)], escalate="strong-model")
    r = o.process_vulnerability(_vuln())
    assert r.status == "unresolved" and r.tiers_used == 3
    calls = o.drv_loop.calls
    assert [c["agent_name"] for c in calls] == ["alpha", "beta", "gamma"]
    assert [c.get("model") for c in calls] == [None, None, "strong-model"]
    assert set(r.agent_reports) == {"alpha", "beta", "gamma"}            # the names are never suffixed
    assert r.agent_models == {"gamma": "strong-model"}                    # the model is recorded instead


def test_without_a_strong_model_nothing_claims_one():
    o = _orch([(False, 5)] * 3, escalate="")
    r = o.process_vulnerability(_vuln())
    assert all(c.get("model") is None for c in o.drv_loop.calls)
    assert r.agent_models == {} and set(r.agent_reports) == {"alpha", "beta", "gamma"}


def test_the_last_tier_can_win_and_the_hand_off_names_every_failed_agent():
    o = _orch([(False, 5), (False, 5), (True, 4)], escalate="strong-model")
    r = o.process_vulnerability(_vuln())
    assert r.status == "patched" and r.winning_agent == "gamma"
    ctx = o.drv_loop.calls[2]["vulnerability_context"]
    assert "(alpha)" in ctx and "(beta)" in ctx


def test_a_crashing_agent_does_not_stop_the_ladder():
    o = _orch([(False, 5)], escalate="")      # replaced below
    original = o.drv_loop.run
    state = {"n": 0}

    def flaky(**kw):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("model unreachable")
        return original(**kw)
    o.drv_loop.run = flaky
    o.drv_loop.script = [(True, 3)]
    r = o.process_vulnerability(_vuln())
    assert r.status == "patched" and r.agent_reports["alpha"] is None and r.tiers_used == 2


def test_explicit_agent_list_keeps_the_old_ensemble_path():
    o = _orch([(True, 5)])
    r = o.process_vulnerability(_vuln(), agents=["alpha"])
    assert r.status == "patched" and r.tiers_used == 0 and len(o.drv_loop.calls) == 1


def test_unknown_strategy_is_rejected():
    with pytest.raises(ValueError):
        Orchestrator(llm_client=FakeLLM(), strategy="vibes")


# -- escalation model: probed, never assumed ---------------------------------------------------

def _client(monkeypatch, base_url, usable, explicit=""):
    from src.agent_orchestrator import llm_client as lc
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_BASE_URL", base_url)
    monkeypatch.setenv("MODEL_ESCALATE", explicit)
    c = lc.LLMClient()
    tried = []

    class Models:
        def retrieve(self, m):
            tried.append(m)
            if m not in usable:
                raise RuntimeError("no access")
    c.client.models = Models()
    return c, tried


def test_escalation_uses_the_first_candidate_this_key_can_call(monkeypatch):
    c, tried = _client(monkeypatch, "https://api.openai.com/v1", usable={"gpt-4.1-mini"})
    assert c.usable_escalate_model() == "gpt-4.1-mini"
    assert tried == ["gpt-4.1", "gpt-4o", "gpt-4.1-mini"]
    assert c.usable_escalate_model() == "gpt-4.1-mini" and len(tried) == 3          # cached


def test_no_usable_model_means_no_escalation_not_a_crash(monkeypatch):
    c, _ = _client(monkeypatch, "https://api.openai.com/v1", usable=set())
    assert c.usable_escalate_model() == ""


def test_other_endpoints_are_never_probed_for_openai_names(monkeypatch):
    c, tried = _client(monkeypatch, "https://ollama.example/v1", usable={"gpt-4o"})
    assert c.usable_escalate_model() == "" and tried == []


def test_an_explicit_escalation_model_is_still_verified(monkeypatch):
    c, tried = _client(monkeypatch, "https://ollama.example/v1", usable={"big:70b"}, explicit="big:70b")
    assert c.usable_escalate_model() == "big:70b" and tried == ["big:70b"]
