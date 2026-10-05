"""
Audit trace and endpoint pinning for model calls.

The rules let the jury demand every LLM query trace, and allow only declared model endpoints. Both are
enforced at one choke point (`LLMClient._create`), so these tests drive that point with a stub server.
"""

import json
from types import SimpleNamespace

import pytest

from src.agent_orchestrator.llm_client import EndpointNotAllowed, LLMClient


class _Completions:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def create(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise self.fail
        msg = SimpleNamespace(content="```diff\n--- a/x\n+++ b/x\n```")
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)],
                               usage=SimpleNamespace(prompt_tokens=11, completion_tokens=7),
                               system_fingerprint="fp_test")


def client(monkeypatch, base="http://localhost:11434/v1", fail=None):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_BASE_URL", base)
    for v in ("KAVACH_ALLOWED_ENDPOINTS", "KAVACH_ALLOWED_MODELS", "KAVACH_LLM_TRACE", "KAVACH_REASONING"):
        monkeypatch.delenv(v, raising=False)
    c = LLMClient()
    comp = _Completions(fail)
    c.client = SimpleNamespace(chat=SimpleNamespace(completions=comp), models=SimpleNamespace())
    c._can_think = lambda model: False                                 # no capability probe over the network
    return c, comp


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


# -- the trace ----------------------------------------------------------------------------------------

def test_every_call_is_traced_with_prompt_response_model_and_tokens(monkeypatch, tmp_path):
    c, _ = client(monkeypatch)
    trace = tmp_path / "trace.jsonl"
    monkeypatch.setenv("KAVACH_LLM_TRACE", str(trace))
    c.generate_patch("alpha", "VULN CONTEXT", model="m")
    c.complete("sys", "user text", purpose="sink-classification", model="m")
    a, b = lines(trace)
    assert a["label"] == "alpha#1" and b["label"] == "sink-classification"
    assert a["model"] == "m" and a["input_tokens"] == 11 and a["output_tokens"] == 7
    assert "VULN CONTEXT" in json.dumps(a["messages"]) and "diff" in a["response"]
    assert a["endpoint"] == "http://localhost:11434/v1" and a["fingerprint"] == "fp_test"
    assert a["seconds"] >= 0 and a["ts"] > 0


def test_the_critic_path_is_traced_too(monkeypatch, tmp_path):
    c, comp = client(monkeypatch)
    trace = tmp_path / "t.jsonl"
    monkeypatch.setenv("KAVACH_LLM_TRACE", str(trace))
    c.structured_call("m", "system", "user", {"name": "v", "schema": {"type": "object"}})
    (rec,) = lines(trace)
    assert rec["label"] == "critic" and "response_format" in comp.calls[0]
    assert "response_format" not in rec["params"]                    # the schema is bulky and not the audit's point


def test_a_failed_call_is_traced_with_its_error(monkeypatch, tmp_path):
    c, _ = client(monkeypatch, fail=ConnectionError("model server down"))
    trace = tmp_path / "t.jsonl"
    monkeypatch.setenv("KAVACH_LLM_TRACE", str(trace))
    with pytest.raises(ConnectionError):
        c._create("m", [{"role": "user", "content": "x"}], label="alpha#1")
    (rec,) = lines(trace)
    assert "model server down" in rec["error"] and "response" not in rec


def test_no_trace_file_is_written_when_tracing_is_off(monkeypatch, tmp_path):
    c, _ = client(monkeypatch)
    c.complete("s", "u", model="m")
    assert list(tmp_path.iterdir()) == []


def test_credentials_in_the_endpoint_never_reach_the_trace(monkeypatch, tmp_path):
    c, _ = client(monkeypatch, base="https://user:secret@models.example:8443/v1")
    trace = tmp_path / "t.jsonl"
    monkeypatch.setenv("KAVACH_LLM_TRACE", str(trace))
    c.complete("s", "u", model="m")
    text = trace.read_text()
    assert "secret" not in text and "models.example:8443" in text


# -- endpoint and model pinning -----------------------------------------------------------------------------

def test_an_undeclared_endpoint_is_refused_before_any_request_is_made(monkeypatch):
    c, comp = client(monkeypatch, base="https://rogue.example/v1")
    monkeypatch.setenv("KAVACH_ALLOWED_ENDPOINTS", "localhost:11434,api.openai.com")
    with pytest.raises(EndpointNotAllowed) as e:
        c.complete("s", "u", model="m")
    assert "rogue.example" in str(e.value) and comp.calls == []


def test_a_declared_endpoint_matches_by_host_or_host_and_port(monkeypatch):
    c, comp = client(monkeypatch)
    monkeypatch.setenv("KAVACH_ALLOWED_ENDPOINTS", "localhost")
    c.complete("s", "u", model="m")
    monkeypatch.setenv("KAVACH_ALLOWED_ENDPOINTS", "localhost:11434")
    c.complete("s", "u", model="m")
    assert len(comp.calls) == 2


def test_an_undeclared_model_is_refused(monkeypatch):
    c, comp = client(monkeypatch)
    monkeypatch.setenv("KAVACH_ALLOWED_MODELS", "gemma")
    c.complete("s", "u", model="gemma")
    with pytest.raises(EndpointNotAllowed):
        c.complete("s", "u", model="other")
    assert len(comp.calls) == 1


def test_a_refusal_is_not_retried(monkeypatch):
    c, comp = client(monkeypatch)
    monkeypatch.setenv("KAVACH_ALLOWED_MODELS", "gemma")
    with pytest.raises(EndpointNotAllowed):
        c._call_with_retry("other", [{"role": "user", "content": "x"}], 50, label="alpha#1")
    assert comp.calls == []


def test_escalation_never_picks_a_model_that_is_not_declared(monkeypatch):
    c, _ = client(monkeypatch, base="https://api.openai.com/v1")
    c.client.models = SimpleNamespace(retrieve=lambda m: None)         # every candidate "exists"
    monkeypatch.setenv("KAVACH_ALLOWED_MODELS", "gpt-4o-mini")
    assert c.usable_escalate_model() == ""


def test_no_restriction_is_applied_when_nothing_is_declared(monkeypatch):
    c, comp = client(monkeypatch, base="https://anywhere.example/v1")
    c.complete("s", "u", model="anything")
    assert len(comp.calls) == 1
