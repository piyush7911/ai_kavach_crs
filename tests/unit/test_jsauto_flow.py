"""
Generic taint-flow analysis for Node apps. Every case is a tiny self-contained app written to a temp
dir. What is pinned down: the analysis recognises requests by role and sinks by imported module,
follows data across files, does not flag sanitised or constant data, and never guesses about a
library it does not know (those go to a classifier, or are reported as unclassified).
"""

import json
from pathlib import Path

import pytest

from src.jsauto import flow
from src.jsauto.classify import _parse, make_classifier


def app(tmp_path, files: dict) -> Path:
    (tmp_path / "package.json").write_text("{}")
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def sinks(a, klass=None):
    return [s for s in a.sinks if klass is None or s.klass == klass]


# -- frameworks and names ---------------------------------------------------------------------

def test_express_named_handler_ssrf(tmp_path):
    a = flow.analyze(app(tmp_path, {"r.js": """
const needle = require("needle");
function fetchIt(req, res) { const u = req.query.base + req.query.sym; needle.get(u, () => {}); }
app.get("/q", fetchIt);
"""}))
    (s,) = sinks(a, "ssrf")
    assert s.function == "fetchIt" and s.entry["route"] == {"method": "GET", "path": "/q"}


def test_request_is_recognised_by_role_not_by_name(tmp_path):
    a = flow.analyze(app(tmp_path, {"zz.js": """
const needle = require("needle");
exports.q = (incomingMsg, outgoingMsg) => { needle.get(incomingMsg.query.target, () => {}); };
"""}))
    assert sinks(a, "ssrf") and a.entry_points[0]["via"] == "request-property-access"


def test_koa_single_parameter_context(tmp_path):
    a = flow.analyze(app(tmp_path, {"k.js": """
const got = require("got");
router.get("/x", async (ctx) => { const r = await got(ctx.query.url); ctx.body = r.body; });
"""}))
    assert [s.klass for s in a.sinks] == ["ssrf"]


def test_fastify_global_fetch(tmp_path):
    a = flow.analyze(app(tmp_path, {"f.js": """
fastify.get("/f", async (request, reply) => { const r = await fetch(request.query.u); return r.text(); });
"""}))
    assert [s.klass for s in a.sinks] == ["ssrf"]


def test_hapi_route_object_and_destructured_import(tmp_path):
    a = flow.analyze(app(tmp_path, {"h.js": """
const { exec } = require("child_process");
server.route({ method: "GET", path: "/h", handler: (request, h) => { exec("ls " + request.query.dir); return "ok"; } });
"""}))
    (s,) = sinks(a, "command-injection")
    assert s.entry["route"]["path"] == "/h"


# -- data flow --------------------------------------------------------------------------------

def test_taint_follows_variables_templates_and_destructuring(tmp_path):
    a = flow.analyze(app(tmp_path, {"p.js": """
const fs = require("fs");
module.exports = (req, res) => {
  const { name } = req.query;
  const full = `/data/${name}.txt`;
  fs.readFile(full, () => {});
};
"""}))
    assert [s.klass for s in a.sinks] == ["path-traversal"]


def test_flow_crosses_files_from_route_into_the_data_layer(tmp_path):
    a = flow.analyze(app(tmp_path, {
        "routes.js": 'const dao = require("./dao");\napp.get("/a", (req, res) => { dao.search(req.query.t, () => {}); });\n',
        "dao.js": "exports.search = (t, cb) => { col.find({ $where: `this.x > '${t}'` }, cb); };\n"}))
    (s,) = sinks(a, "nosql-injection")
    assert s.file == "dao.js" and len(s.chain) == 2 and s.entry["route"]["path"] == "/a"


def test_sanitised_and_constant_data_is_not_flagged(tmp_path):
    a = flow.analyze(app(tmp_path, {"s.js": """
const fs = require("fs"); const needle = require("needle");
app.get("/s", (req, res) => {
  fs.readFile("/etc/static.txt", () => {});
  needle.get("https://example.com/" + encodeURIComponent(req.query.q), () => {});
  const n = parseInt(req.query.n, 10);
  fs.readFile("/data/" + n, () => {});
  eval("1+1");
});
"""}))
    assert a.sinks == []


def test_calling_a_callback_parameter_is_not_a_sink(tmp_path):
    a = flow.analyze(app(tmp_path, {"c.js": 'app.get("/c", (req, res, next) => { next(req.query.x); });\n'}))
    assert a.sinks == [] and a.unclassified == []


def test_response_redirect_is_a_sink_only_with_user_data(tmp_path):
    a = flow.analyze(app(tmp_path, {"r.js": """
app.get("/go", (req, res) => { res.redirect(req.query.next); });
app.get("/home", (req, res) => { res.redirect("/home"); });
"""}))
    assert [(s.klass, s.entry["route"]["path"]) for s in a.sinks] == [("open-redirect", "/go")]


# -- calls the knowledge file does not know ----------------------------------------------------

UNLISTED = {"u.js": 'const sa = require("brand-new-http-lib");\napp.get("/u", (req, res) => { sa.fetchUrl(req.query.u); });\n'}


def test_unknown_library_is_reported_unclassified_not_guessed_and_not_dropped(tmp_path):
    a = flow.analyze(app(tmp_path, UNLISTED))
    assert a.sinks == [] and [u.callee for u in a.unclassified] == ["sa.fetchUrl"]
    assert a.unclassified[0].module == "brand-new-http-lib"


def test_unknown_library_is_classified_by_the_model_with_low_confidence(tmp_path):
    asked = []

    def stub(u):
        asked.append(u.callee)
        return {"sink": True, "class": "ssrf", "cwe": "CWE-918"}

    a = flow.analyze(app(tmp_path, UNLISTED), classifier=stub)
    (s,) = a.sinks
    assert (s.klass, s.classified_by, s.confidence) == ("ssrf", "model", "low") and asked == ["sa.fetchUrl"]


def test_a_model_that_says_not_a_sink_leaves_the_call_unclassified(tmp_path):
    a = flow.analyze(app(tmp_path, UNLISTED), classifier=lambda u: {"sink": False})
    assert a.sinks == [] and len(a.unclassified) == 1


def test_each_distinct_call_is_asked_once(tmp_path):
    files = {"m.js": 'const sa = require("x-lib");\napp.get("/1", (req, res) => { sa.go(req.query.a); });\n'
                     'app.get("/2", (req, res) => { sa.go(req.query.b); });\n'}
    asked = []
    flow.analyze(app(tmp_path, files), classifier=lambda u: asked.append(u.callee) or None)
    assert asked == ["sa.go"]


# -- classifier output handling --------------------------------------------------------------------

def test_verdict_parsing_rejects_anything_that_does_not_validate():
    assert _parse('{"sink": true, "class": "ssrf", "cwe": "CWE-918"}')["class"] == "ssrf"
    assert _parse('noise {"sink": false} noise') == {"sink": False}
    assert _parse("I think it might be dangerous") is None
    assert _parse('{"sink": true, "class": "made-up"}') is None
    assert _parse('{"sink": true, "class": "none"}') is None
    assert _parse('{"sink": "yes", "class": "ssrf"}') is None
    assert _parse('{"sink": true, "class": "ssrf", "cwe": "bad"}')["cwe"] == ""


def test_classifier_caches_answers_on_disk(tmp_path):
    class LLM:
        calls = 0

        def complete(self, *a, **k):
            LLM.calls += 1
            return '{"sink": true, "class": "xss", "cwe": "CWE-79"}'

    class U:
        module, callee, arg_index, tainted_expr, snippet = "m", "m.render", 0, "req.query.x", "code"
        entry = {"function": "h", "route": {"method": "GET", "path": "/"}}

    path = tmp_path / "learned.json"
    c1 = make_classifier(LLM(), learned_path=path)
    c2 = make_classifier(LLM(), learned_path=path)
    assert c1(U())["class"] == "xss" and c2(U())["class"] == "xss"
    assert LLM.calls == 1 and json.loads(path.read_text())["m::render"]["sink"] is True


# -- integration with the scan --------------------------------------------------------------------

def test_scan_merges_flow_and_semgrep_into_one_finding_per_defect(tmp_path):
    from src.jsauto import static
    root = app(tmp_path, {"r.js": """
const needle = require("needle");
app.get("/q", (req, res) => { needle.get(req.query.u, () => {}); });
"""})
    out = static.scan(root)
    (f,) = [x for x in out["findings"] if x.klass == "ssrf"]
    assert set(f.evidence["detected_by"]) == {"flow", "semgrep"}
    assert f.evidence["entry"]["route"] == {"method": "GET", "path": "/q"}
    assert out["entry_points"] and f.function == "<anonymous@3>"


def test_a_failing_classifier_is_reported_and_the_call_stays_unclassified(tmp_path):
    def broken(u):
        raise ConnectionError("model server down")

    a = flow.analyze(app(tmp_path, UNLISTED), classifier=broken)
    assert a.sinks == [] and len(a.unclassified) == 1
    assert a.classifier_calls == 1 and "model server down" in a.classifier_errors[0]
