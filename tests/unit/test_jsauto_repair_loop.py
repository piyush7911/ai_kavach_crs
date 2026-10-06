"""
The JavaScript repair loop, driven by a scripted model and stub gates: no model server, no running app.
What is pinned down: rejections are fed back, the original tree is never modified, a skipped gate is never
a pass, a failing model is reported, and dependency fixes are deterministic and conservative.
"""

import json
from pathlib import Path

import pytest

from src.jsauto import repair as R

SOURCE = """const express = require("express");

function Handler() {
    this.compute = (req, res) => {
        const a = eval(req.body.a);
        const b = eval(req.body.b);
        const total = a + b;
        const note = "sum";
        const out = { total, note };
        const log = [a, b];
        return res.json(out);
    };
    this.other = (req, res) => { res.send("x"); };
}
module.exports = Handler;
"""

GOOD = """```js
this.compute = (req, res) => {
        const a = Number(req.body.a);
        const b = Number(req.body.b);
        if (Number.isNaN(a) || Number.isNaN(b)) { return res.status(400).send("bad"); }
        const total = a + b;
        const note = "sum";
        const out = { total, note };
        const log = [a, b];
        return res.json(out);
    };
```"""

GOOD2 = GOOD.replace('"bad"', '"bad input"')         # behaves the same, but is a different answer
GOOD3 = GOOD.replace('"bad"', '"invalid"')
CHEAT2 = None  # defined below, after CHEAT
CHEAT = GOOD.replace("const total", 'require("child_process").exec("curl x");\n        const total', 1)

CHEAT2 = CHEAT.replace("curl x", "curl y")
EXPLOIT = {"method": "POST", "path": "/c", "success_if": {"body_regex": "31338"}}


def finding(exploit=EXPLOIT):
    f = {"id": "JS-1", "klass": "eval-injection", "cwe": "CWE-95", "severity": "high", "file": "routes.js",
         "line": 5, "function": "compute", "message": "user data reaches eval",
         "evidence": {"tainted_expr": "req.body.a", "callee": "eval", "chain": ["routes.js:compute"],
                      "entry": {"function": "compute", "file": "routes.js",
                                "route": {"method": "POST", "path": "/c"}}}}
    if exploit is not None:
        f["exploit"] = exploit
    return f


class ScriptedModel:
    def __init__(self, *answers, escalate=""):
        self.answers, self.prompts, self.systems, self.models = list(answers), [], [], []
        self.escalate = escalate

    def usable_escalate_model(self):
        return self.escalate

    def complete(self, system, prompt, purpose="", max_tokens=0, model=None):
        self.prompts.append(prompt)
        self.systems.append(system)
        self.models.append(model)
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


class StubGates:
    def __init__(self, start=None, replay=None, regress=None):
        self.s, self.p, self.g = list(start or []), list(replay or []), list(regress or [])
        self.calls = []

    def _next(self, queue, name, default):
        self.calls.append(name)
        return queue.pop(0) if queue else default

    def start(self, tree):
        return self._next(self.s, "start", (R.PASS, "healthy"))

    def replay(self, tree, exploit):
        return self._next(self.p, "replay", (R.PASS, "not exploitable"))

    def regress(self, tree):
        return self._next(self.g, "regress", (R.PASS, "flows match"))


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "app"
    r.mkdir()
    (r / "routes.js").write_text(SOURCE)
    (r / "package.json").write_text('{\n  "dependencies": {\n    "express": "^4.16.4"\n  }\n}\n')
    return r


def test_a_good_first_answer_is_proven_and_the_original_tree_is_untouched(root):
    out = R.repair(finding(), root, ScriptedModel(GOOD), StubGates())
    assert out.status == "proven" and len(out.attempts) == 1 and out.attempts[0].stage == "accepted"
    assert out.gates == {"start": R.PASS, "pov": R.PASS, "regression": R.PASS, "hardening": R.SKIPPED}
    assert "-        const a = eval(req.body.a);" in out.diff and "+        const a = Number(req.body.a);" in out.diff
    assert (root / "routes.js").read_text() == SOURCE                     # a diff is returned, nothing applied


def test_a_policy_violation_is_rejected_and_the_reason_goes_back_to_the_model(root):
    model = ScriptedModel(CHEAT, GOOD)
    out = R.repair(finding(), root, model, StubGates())
    assert out.status == "proven" and [a.stage for a in out.attempts] == ["policy", "accepted"]
    assert "YOUR PREVIOUS ATTEMPT WAS REJECTED" in model.prompts[1] and "shell_execution" in model.prompts[1]
    assert "REJECTED" not in model.prompts[0]


def test_a_failed_proof_of_vulnerability_gate_is_fed_back_and_the_next_attempt_can_pass(root):
    gates = StubGates(replay=[(R.FAIL, "still exploitable: marker 31338 in body"), (R.PASS, "ok")])
    model = ScriptedModel(GOOD, GOOD2)
    out = R.repair(finding(), root, model, gates)
    assert out.status == "proven" and out.attempts[0].stage == "pov"
    assert "pov gate failed" in model.prompts[1] and "31338" in model.prompts[1]


def test_a_regression_failure_stops_the_attempt_and_restores_the_original(root, tmp_path):
    work = tmp_path / "work"
    gates = StubGates(regress=[(R.FAIL, "flow login: status 500")] * 2)
    out = R.repair(finding(), root, ScriptedModel(GOOD, GOOD2), gates, max_attempts=2, workdir=work)
    assert out.status == "unresolved" and [a.stage for a in out.attempts] == ["regression", "regression"]
    assert (work / "tree" / "routes.js").read_text() == SOURCE            # the failed patch was backed out
    assert "no attempt passed in 2 tries" in out.reason and "flow login" in out.reason


def test_without_an_exploit_the_pov_gate_is_skipped_and_the_result_is_not_proven(root):
    gates = StubGates()
    out = R.repair(finding(exploit=None), root, ScriptedModel(GOOD), gates)
    assert out.status == "patched_unproven" and out.gates["pov"] == R.SKIPPED
    assert "replay" not in gates.calls and "skipped gates are never counted as a pass" in out.reason


def test_a_tree_that_will_not_start_fails_before_any_exploit_is_replayed(root):
    gates = StubGates(start=[(R.FAIL, "port in use")] * 3)
    out = R.repair(finding(), root, ScriptedModel(GOOD, GOOD2, GOOD3), gates)
    assert out.status == "unresolved" and "replay" not in gates.calls and out.attempts[0].stage == "start"


def test_a_failing_model_is_reported_not_swallowed(root):
    out = R.repair(finding(), root, ScriptedModel(ConnectionError("model server down")), StubGates())
    assert out.status == "error" and "model server down" in out.reason and out.attempts[0].stage == "generation"


def test_an_unlocatable_function_is_an_error_not_a_guess(root):
    f = finding()
    f["function"] = "missing"
    out = R.repair(f, root, ScriptedModel(), StubGates())
    assert out.status == "error" and "cannot locate" in out.reason


def test_an_answer_that_is_not_code_is_rejected_as_unparseable(root):
    out = R.repair(finding(), root, ScriptedModel("I am unable to help.", GOOD), StubGates())
    assert out.status == "proven" and out.attempts[0].stage in ("apply", "policy")


# -- dependency fixes ------------------------------------------------------------------------------------------

def dep(fix="4.20.0", major=False, via=None):
    return {"id": "JS-9", "klass": "vulnerable-dependency", "file": "package.json", "function": "",
            "evidence": {"package": "express", "installed": "4.16.4", "fix_version": fix,
                         "fix_is_major_bump": major, "via_packages": via or []}}


def test_a_dependency_fix_is_advisory_only_not_applied(root):
    # air-gapped: we RECOMMEND the version (suggested diff shown) but never edit/test offline
    model = ScriptedModel()                                              # the model is never consulted
    out = R.repair(dep(), root, model, StubGates())
    assert out.status == "advisory" and '+    "express": "^4.20.0"' in out.diff
    assert model.prompts == [] and "NOT applied" in out.reason and out.new_text == ""
    assert "4.16.4" in (root / "package.json").read_text()                # manifest untouched


def test_a_major_bump_is_advisory_and_flags_human_decision(root):
    out = R.repair(dep(fix="5.0.0", major=True), root, ScriptedModel(), StubGates())
    assert out.status == "advisory" and "major version bump" in out.reason and out.diff == ""


def test_a_transitive_vulnerability_has_no_fix_the_loop_can_apply(root):
    out = R.repair(dep(fix="", via=["qs"]), root, ScriptedModel(), StubGates())
    assert out.status == "unresolved" and "no published fix" in out.reason and "qs" in out.reason


def test_a_dependency_that_is_not_declared_is_an_error(root):
    f = dep()
    f["evidence"]["package"] = "left-pad"
    out = R.repair(f, root, ScriptedModel(), StubGates())
    assert out.status == "error" and "not a dependency" in out.reason


# -- the runner adapter -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("code,expected", [(0, R.PASS), (1, R.FAIL), (2, R.FAIL), (124, R.FAIL)])
def test_replay_exit_codes_map_to_gate_states(monkeypatch, code, expected):
    g = R.RunnerGates(module="some.runner")
    monkeypatch.setattr(g, "_run", lambda *a: (code, "text"))
    state, detail = g.replay(Path("."), {"method": "GET", "path": "/"})
    assert state == expected
    if code == 0:
        assert "no longer exploitable" in detail
    if code == 1:
        assert "still exploitable" in detail


def test_start_and_regress_pass_only_on_exit_zero(monkeypatch):
    g = R.RunnerGates(module="some.runner")
    monkeypatch.setattr(g, "_run", lambda *a: (0, "ok"))
    assert g.start(Path("."))[0] == R.PASS and g.regress(Path("."))[0] == R.PASS
    monkeypatch.setattr(g, "_run", lambda *a: (1, "diverged"))
    assert g.start(Path("."))[0] == R.FAIL and g.regress(Path("."))[0] == R.FAIL


def test_the_exploit_is_handed_to_the_runner_as_a_file_and_cleaned_up(monkeypatch):
    seen = {}

    def fake_run(*args):
        path = Path(args[args.index("--exploit") + 1])
        seen["body"] = json.loads(path.read_text())
        seen["path"] = path
        return 0, ""
    g = R.RunnerGates(module="some.runner")
    monkeypatch.setattr(g, "_run", fake_run)
    g.replay(Path("."), EXPLOIT)
    assert seen["body"] == EXPLOIT and not seen["path"].exists()


def test_a_runner_must_be_configured_there_is_no_default(monkeypatch):
    monkeypatch.delenv("KAVACH_RUNNER_MODULE", raising=False)
    with pytest.raises(ValueError) as e:
        R.RunnerGates()
    assert "KAVACH_RUNNER_MODULE" in str(e.value)
    monkeypatch.setenv("KAVACH_RUNNER_MODULE", "pkg.runner")
    assert R.RunnerGates().module == "pkg.runner"


# -- hardening: other spellings of the exploit ---------------------------------------------------------------------

VARIANTS = [{"method": "POST", "path": f"/c?v={i}", "success_if": {}} for i in range(3)]


class VariantGates(StubGates):
    """Primary exploit blocked, but variant `leaks` (1-based) still works until the patch changes."""

    def __init__(self, leaks=None, **kw):
        super().__init__(**kw)
        self.leaks, self.seen = leaks, []

    def replay(self, tree, exploit):
        self.seen.append(exploit["path"])
        if self.leaks and exploit["path"] == f"/c?v={self.leaks - 1}":
            return R.FAIL, "still exploitable: marker in body"
        return R.PASS, "no longer exploitable"


def test_a_patch_that_blocks_every_variant_is_hardened(root):
    gates = VariantGates()
    out = R.repair(finding(), root, ScriptedModel(GOOD), gates, variants=VARIANTS)
    assert out.status == "proven" and out.hardened is True and out.gates["hardening"] == R.PASS
    assert gates.seen == [EXPLOIT["path"]] + [v["path"] for v in VARIANTS]
    assert out.reason == "every gate passed"


def test_a_leaking_variant_rejects_the_patch_and_is_named_to_the_model(root):
    gates = VariantGates(leaks=2)
    model = ScriptedModel(GOOD, GOOD2)
    out = R.repair(finding(), root, model, gates, max_attempts=2, variants=VARIANTS)
    assert out.status == "unresolved" and [a.stage for a in out.attempts] == ["hardening", "hardening"]
    assert "variant 2 of 3 still works" in model.prompts[1] and "not one spelling of it" in model.prompts[1]
    assert out.hardened is False and out.new_text == ""


def test_variants_are_not_replayed_when_the_primary_exploit_is_still_working(root):
    gates = VariantGates()
    gates_primary_fails = StubGates(replay=[(R.FAIL, "still exploitable")] * 2)
    out = R.repair(finding(), root, ScriptedModel(GOOD, GOOD2), gates_primary_fails, max_attempts=2, variants=VARIANTS)
    assert out.attempts[0].stage == "pov" and gates.seen == []


def test_no_variants_are_replayed_without_a_primary_exploit(root):
    gates = VariantGates()
    out = R.repair(finding(exploit=None), root, ScriptedModel(GOOD), gates, variants=VARIANTS)
    assert gates.seen == [] and out.gates["hardening"] == R.SKIPPED and out.status == "patched_unproven"


# -- an identical answer is not retried ---------------------------------------------------------------------------

def test_the_same_answer_twice_stops_the_loop_instead_of_asking_a_third_time(root):
    model = ScriptedModel(CHEAT, CHEAT, GOOD)
    out = R.repair(finding(), root, model, StubGates(), max_attempts=3)
    assert out.status == "unresolved" and len(model.prompts) == 2 and model.answers == [GOOD]
    assert [a.stage for a in out.attempts] == ["policy", "repeat"]
    assert "same answer as attempt 1" in out.reason and "shell_execution" in out.reason


def test_different_answers_are_still_all_tried(root):
    out = R.repair(finding(), root, ScriptedModel(CHEAT, GOOD), StubGates(), max_attempts=3)
    assert out.status == "proven" and [a.stage for a in out.attempts] == ["policy", "accepted"]


# -- the adaptive ladder: alpha, then beta, then gamma on a stronger model -----------------------------------------

def test_an_easy_bug_costs_one_call_under_the_adaptive_strategy(root):
    model = ScriptedModel(GOOD)
    out = R.repair(finding(), root, model, StubGates(), max_attempts=2, strategy="adaptive")
    assert out.status == "proven" and len(model.prompts) == 1 and out.attempts[0].agent == "alpha"


def test_a_failed_tier_hands_over_to_the_next_agent_with_what_was_tried(root):
    model = ScriptedModel(CHEAT, CHEAT2, GOOD)                          # alpha twice rejected, beta fixes it
    out = R.repair(finding(), root, model, StubGates(), max_attempts=2, strategy="adaptive")
    assert out.status == "proven" and [a.agent for a in out.attempts] == ["alpha", "alpha", "beta"]
    assert "Work out the root cause" in model.systems[0] and "SMALLEST change" in model.systems[2]
    assert "EARLIER ATTEMPTS" in model.prompts[2] and "(alpha) policy" in model.prompts[2]


def test_the_last_tier_uses_the_stronger_model_only_if_one_is_declared(root):
    answers = [CHEAT, CHEAT2, GOOD3.replace("bad", "x"), GOOD2.replace("input", "inputs"), GOOD, GOOD2]
    gates = StubGates(regress=[(R.FAIL, "flow broke")] * 4)
    with_big = ScriptedModel(*[a + f"\n// {i}" for i, a in enumerate(answers)], escalate="big-model")
    R.repair(finding(), root, with_big, gates, max_attempts=2, strategy="adaptive")
    assert with_big.models[:4] == [None] * 4 and with_big.models[4:] == ["big-model", "big-model"]
    without = ScriptedModel(*[a + f"\n// {i}" for i, a in enumerate(answers)], escalate="")
    R.repair(finding(), root, without, StubGates(regress=[(R.FAIL, "flow broke")] * 4), max_attempts=2, strategy="adaptive")
    assert without.models == [None] * 6


def test_a_repeated_answer_skips_the_rest_of_that_agent_and_moves_on(root):
    model = ScriptedModel(CHEAT, CHEAT, GOOD)
    out = R.repair(finding(), root, model, StubGates(), max_attempts=2, strategy="adaptive")
    assert out.status == "proven" and [(a.agent, a.stage) for a in out.attempts] == [
        ("alpha", "policy"), ("alpha", "repeat"), ("beta", "accepted")]


def test_the_single_strategy_only_ever_uses_alpha(root):
    model = ScriptedModel(CHEAT, CHEAT2, GOOD)
    out = R.repair(finding(), root, model, StubGates(), max_attempts=3)
    assert {a.agent for a in out.attempts} == {"alpha"} and out.status == "proven"


def test_the_agent_and_model_are_recorded_in_the_outcome(root):
    out = R.repair(finding(), root, ScriptedModel(GOOD), StubGates(), strategy="adaptive")
    d = out.to_dict()["attempts"][0]
    assert d["agent"] == "alpha" and d["model"] == ""
