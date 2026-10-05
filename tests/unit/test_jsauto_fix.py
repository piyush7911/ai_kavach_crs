"""
The confirm -> variants -> repair -> harden -> final-check cycle (src/jsauto/fix.py), driven by a stub
runner that calls a tree vulnerable while its routes.js still contains `eval(`. No app, no model server.
"""

import json
from pathlib import Path

import pytest

from src.jsauto import fix
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


class Model:
    def __init__(self, *answers):
        self.answers, self.usage_log = list(answers), []

    def complete(self, system, prompt, purpose="", max_tokens=0):
        self.usage_log.append(purpose)
        return self.answers.pop(0)


class Runner:
    """A tree is vulnerable while routes.js contains `eval(`. Knobs let a test change what the runner says."""

    def __init__(self, reproduces=True, only_first_variant_works=False, regress=R.PASS):
        self.reproduces, self.only_first, self.regress_state = reproduces, only_first_variant_works, regress
        self.calls = []

    def _vulnerable(self, tree):
        return "eval(" in (Path(tree) / "routes.js").read_text()

    def exploitable(self, tree, exploit):
        self.calls.append(("exploitable", Path(tree).name, exploit["path"]))
        if not self._vulnerable(tree):
            return False, "not exploitable"
        if not self.reproduces:
            return False, "exploit did not work"
        if self.only_first and exploit.get("body", {}).get("a") not in ("31337+1",):
            return False, "this spelling never worked"
        return True, "worked"

    def start(self, tree):
        return R.PASS, "healthy"

    def replay(self, tree, exploit):
        works, detail = self.exploitable(tree, exploit)
        return (R.FAIL, "still exploitable: " + detail) if works else (R.PASS, "no longer exploitable")

    def regress(self, tree):
        return self.regress_state, "flows"


def finding(i=1, klass="eval-injection", function="compute", **extra):
    f = {"id": f"JS-{i:03d}", "klass": klass, "cwe": "CWE-95", "severity": "high", "file": "routes.js",
         "line": 5, "function": function, "message": "user data reaches eval",
         "evidence": {"tainted_expr": "req.body.a", "callee": "eval", "chain": ["routes.js:compute"],
                      "entry": {"function": "compute", "file": "routes.js",
                                "route": {"method": "POST", "path": "/c"}}}}
    f.update(extra)
    return f


@pytest.fixture
def app(tmp_path):
    r = tmp_path / "app"
    r.mkdir()
    (r / "routes.js").write_text(SOURCE)
    (r / "package.json").write_text('{"dependencies": {}}')
    return r


def go(app, tmp_path, findings, runner=None, model=None, **kw):
    out = tmp_path / "out"
    ev = fix.run(app, runner or Runner(), model or Model(*[GOOD] * 6), out, findings=findings, **kw)
    return ev, out


def test_the_whole_cycle_proves_hardens_and_re_checks_the_final_tree(app, tmp_path):
    ev, out = go(app, tmp_path, [finding()])
    (e,) = ev["findings"]
    assert e["status"] == "proven" and e["hardened"] is True and e["confirmed"] is True
    assert e["variants"] == {"kept": 4, "of": 4}
    assert e["gates"] == {"start": R.PASS, "pov": R.PASS, "regression": R.PASS, "hardening": R.PASS}
    fc = ev["final_check"]
    assert fc["start"] == R.PASS and fc["regression"] == R.PASS
    assert fc["confirmed_exploits_blocked"] == ["JS-001"] and fc["confirmed_exploits_still_working"] == []
    assert "Number(req.body.a)" in (out / "combined" / "routes.js").read_text()
    assert (app / "routes.js").read_text() == SOURCE                      # the original is never modified
    assert "routes.js" in (out / "final.diff").read_text() and (out / "patches" / "JS-001.diff").exists()
    assert json.loads((out / "evidence.json").read_text())["by_status"] == {"proven": 1}


def test_an_exploit_that_does_not_reproduce_is_dropped_and_the_result_is_never_proven(app, tmp_path):
    ev, _ = go(app, tmp_path, [finding()], runner=Runner(reproduces=False))
    (e,) = ev["findings"]
    assert e["confirmed"] is False and "did not reproduce" in e["unconfirmed_reason"]
    assert e["status"] == "patched_unproven" and e["gates"]["pov"] == R.SKIPPED
    assert ev["final_check"]["confirmed_exploits_blocked"] == []          # nothing was confirmed to be blocked


def test_variants_that_never_worked_on_the_original_are_not_used_to_judge_the_patch(app, tmp_path):
    ev, _ = go(app, tmp_path, [finding()], runner=Runner(only_first_variant_works=True))
    (e,) = ev["findings"]
    assert e["variants"] == {"kept": 0, "of": 4}
    assert e["status"] == "proven" and e["hardened"] is False and e["gates"]["hardening"] == R.SKIPPED
    assert "no exploit variants were replayed" in e["reason"]


def test_a_regression_failure_leaves_the_finding_unresolved_and_the_tree_unchanged(app, tmp_path):
    ev, out = go(app, tmp_path, [finding()], runner=Runner(regress=R.FAIL), attempts=2,
                 model=Model(GOOD, GOOD))
    (e,) = ev["findings"]
    assert e["status"] == "unresolved" and [a["stage"] for a in e["attempts"]] == ["regression", "regression"]
    assert "eval(" in (out / "combined" / "routes.js").read_text() and not (out / "patches" / "JS-001.diff").exists()


def test_a_later_finding_is_already_fixed_when_an_earlier_patch_removed_its_cause(app, tmp_path):
    model = Model(GOOD)                                                    # only one model answer is available
    ev, _ = go(app, tmp_path, [finding(1), finding(2)], model=model)
    first, second = ev["findings"]
    assert first["status"] == "proven" and second["status"] == "already_fixed"
    assert "earlier patches" in second["reason"] and len(model.usage_log) == 1


def test_a_committed_private_key_is_reported_as_not_fixable_by_a_code_edit(app, tmp_path):
    key = finding(1, klass="private-key-in-repo", function="")
    ev, _ = go(app, tmp_path, [key])
    (e,) = ev["findings"]
    assert e["status"] == "not_a_code_fix" and "rotated" in e["reason"]


def test_informational_and_suppressed_findings_are_listed_but_not_repaired(app, tmp_path):
    info = finding(1, klass="hardcoded-secret", status="informational")
    ev, _ = go(app, tmp_path, [info, finding(2)])
    assert [e["id"] for e in ev["findings"]] == ["JS-002"]
    assert ev["skipped"] == [{"id": "JS-001", "klass": "hardcoded-secret", "status": "informational"}]


def test_findings_are_taken_most_severe_first_and_can_be_limited_or_filtered(app, tmp_path):
    low = finding(1, severity="low")
    crit = finding(2, severity="critical")
    ev, _ = go(app, tmp_path, [low, crit], runner=Runner(reproduces=False), max_findings=1,
               model=Model(GOOD))
    assert [e["id"] for e in ev["findings"]] == ["JS-002"]
    ev, _ = go(app, tmp_path, [finding(1), finding(2, klass="ssrf")], classes={"ssrf"},
               runner=Runner(reproduces=False), model=Model(GOOD))
    assert {e["klass"] for e in ev["findings"]} == {"ssrf"}


def test_the_model_call_count_in_the_evidence_is_this_runs_own(app, tmp_path):
    ev, _ = go(app, tmp_path, [finding()])
    assert ev["model_calls"] == 1 and ev["attempted"] == 1
