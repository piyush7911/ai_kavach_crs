"""
Structural vulnerability classes found by general rules, not by a list of sinks: cross-site scripting through
templates, insecure direct object references, and missing CSRF protection.

Every rule is checked in both directions (the positive case, and the near-miss that must NOT be flagged), because
a rule that fires on the wrong thing is how a detector gets tuned to one application. A rename-mutation test
repeats the whole detection on an application whose names have all been changed.
"""

import json
from pathlib import Path

import pytest

from src.jsauto import flow, probes, static
from src.jsauto.templates import TemplateIndex, load_knowledge, scan_text

ROOT = Path(__file__).resolve().parents[2]
NODEGOAT = ROOT / "benchmark_workspace" / "nodegoat"
URL_ATTRS = set(load_knowledge()["url_attributes"])


def app(tmp_path, files: dict) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "package.json").write_text("{}")
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def one(tpl, var="x"):
    sites = [s for s in scan_text(tpl, "t.html", URL_ATTRS) if s.var == var]
    assert len(sites) == 1, sites
    return sites[0]


def klasses(a, klass):
    return [s for s in a.sinks if s.klass == klass]


# -- template contexts --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("tpl,context", [
    ('<a href="{{x}}">l</a>', "url-start"),
    ('<a href=" {{x}}">l</a>', "url-start"),
    ('<a href="/p?q={{x}}">l</a>', "url"),
    ('<img src={{x}}>', "url-start"),
    ('<form action="{{x}}">', "url-start"),
    ('<button onclick="go(\'{{x}}\')">', "event"),
    ('<script>var a = "{{x}}";</script>', "script"),
    ('<style>.a { color: {{x}} }</style>', "css"),
    ('<p style="color: {{x}}">t</p>', "css"),
    ('<input value="{{x}}">', "attr"),
    ('<p>{{x}}</p>', "html"),
    ('<script>1</script><p>{{x}}</p>', "html"),
])
def test_the_html_context_of_a_print_site(tpl, context):
    assert one(tpl).context == context


@pytest.mark.parametrize("tpl,raw", [
    ("<p>{{{x}}}</p>", True), ("<p>{{ x | safe }}</p>", True), ("<p>{{ x|raw }}</p>", True),
    ("<p><%- x %></p>", True), ("<p>!{x}</p>", True),
    ("<p>{{x}}</p>", False), ("<p><%= x %></p>", False), ("<p>#{x}</p>", False),
])
def test_raw_versus_escaped_output_in_each_template_syntax(tpl, raw):
    assert one(tpl).raw is raw


def test_block_partial_and_comment_tags_are_not_print_sites():
    sites = scan_text("{{#if x}}a{{/if}}{{> part}}{{! note }}{{^x}}b{{/x}}", "t.hbs", URL_ATTRS)
    assert sites == []


def test_the_root_variable_of_an_expression_is_what_the_handler_must_have_passed():
    s = one("<p>{{ user.name | safe }}</p>", "user")
    assert s.var == "user" and s.raw


def test_which_contexts_are_dangerous():
    assert one('<a href="{{x}}">').dangerous and one('<b onclick="{{x}}">').dangerous
    assert one("<script>{{x}}</script>").dangerous and one("<p>{{{x}}}</p>").dangerous
    assert not one("<p>{{x}}</p>").dangerous and not one('<input value="{{x}}">').dangerous
    assert not one('<a href="/p?q={{x}}">').dangerous


def test_the_template_index_matches_views_by_path_and_skips_vendored_and_static_files(tmp_path):
    app(tmp_path, {"views/admin/users.html": "<p>{{n}}</p>", "views/home.ejs": "<%= n %>",
                   "node_modules/x/t.html": "{{n}}", "public/p.html": "{{n}}", "test/t.html": "{{n}}"})
    t = TemplateIndex(tmp_path)
    assert sorted(t.by_file) == ["views/admin/users.html", "views/home.ejs"]
    assert t.sites_for("admin/users") and t.sites_for("users") and t.sites_for("home")
    assert t.sites_for("sers") == [] and t.sites_for("p") == []


# -- cross-site scripting through render ----------------------------------------------------------------------------

def test_a_request_value_at_the_start_of_a_url_attribute_is_xss_whatever_the_handler_did(tmp_path):
    a = flow.analyze(app(tmp_path, {
        "routes.js": 'app.post("/p", (req, res) => { const { name } = req.body; const label = name;\n'
                     '  res.render("p", { label, other: 1 }); });\n',
        "views/p.html": '<a href="{{label}}">go</a>'}))
    (s,) = klasses(a, "xss")
    assert s.file == "routes.js" and s.line == 2 and s.fields == [["body", "name"]] and s.confidence == "high"
    assert s.extra["context"] == "url-start" and s.extra["template"] == "views/p.html" and s.extra["variable"] == "label"


def test_a_request_value_printed_raw_is_xss_in_any_engine(tmp_path):
    a = flow.analyze(app(tmp_path, {
        "routes.js": 'app.get("/m", (req, res) => { res.render("m", { msg: req.query.msg }); });\n',
        "views/m.ejs": "<p><%- msg %></p>"}))
    (s,) = klasses(a, "xss")
    assert s.extra["raw"] is True and s.fields == [["query", "msg"]]


def test_the_request_object_can_have_any_name(tmp_path):
    a = flow.analyze(app(tmp_path, {
        "routes.js": 'app.get("/m", (incoming, outgoing) => { outgoing.render("m", { msg: incoming.query.msg }); });\n',
        "views/m.html": "<p>{{{msg}}}</p>"}))
    assert len(klasses(a, "xss")) == 1


@pytest.mark.parametrize("handler,template", [
    ('res.render("p", { msg: req.query.msg });', "<p>{{msg}}</p>"),                       # escaped, plain HTML context
    ('res.render("p", { msg: req.query.msg });', '<input value="{{msg}}">'),             # escaped attribute value
    ('res.render("p", { msg: req.query.msg });', '<a href="/s?q={{msg}}">x</a>'),        # not the start of a URL
    ('res.render("p", { msg: "static" });', "<p>{{{msg}}}</p>"),                           # not from the request
    ('res.render("p", { other: req.query.msg });', "<p>{{{msg}}}</p>"),                   # the template prints a different variable
    ('res.render("p", { ...stored });', "<p>{{{msg}}}</p>"),                              # data of unknown origin is not guessed at
    ('res.render("p", { msg: escapeHtml(req.query.msg) });', "<p>{{{msg}}}</p>"),         # sanitised before printing
])
def test_near_misses_are_not_flagged(tmp_path, handler, template):
    a = flow.analyze(app(tmp_path, {
        "routes.js": f'app.get("/p", (req, res) => {{ const stored = {{}}; {handler} }});\n',
        "views/p.html": template}))
    assert klasses(a, "xss") == []


def test_a_render_of_a_view_that_does_not_exist_is_ignored(tmp_path):
    a = flow.analyze(app(tmp_path, {"routes.js": 'app.get("/p", (req, res) => { res.render("nope", { m: req.query.m }); });\n'}))
    assert klasses(a, "xss") == []


# -- insecure direct object references -------------------------------------------------------------------------------

def idor(tmp_path, handler, route='app.get("/a/:userId", isLoggedIn, H);'):
    a = flow.analyze(app(tmp_path, {
        "routes.js": f"const H = (req, res) => {{\n{handler}\n}};\n{route}\n"}))
    return klasses(a, "idor")


def test_a_client_supplied_identifier_used_as_the_lookup_key_with_no_ownership_check_is_idor(tmp_path):
    (s,) = idor(tmp_path, "  const { userId } = req.params;\n  dao.getByUserId(userId, () => {});")
    assert s.fields == [["params", "userId"]] and s.confidence == "medium"
    assert s.line == 2 and s.extra["identifier"] == "userId" and "never compared" in s.extra["authorization_check"]


def test_a_generic_id_field_is_reported_with_low_confidence(tmp_path):
    (s,) = idor(tmp_path, "  const id = req.query.id;\n  db.Product.find({ where: { id } }, () => {});")
    assert s.confidence == "low"


@pytest.mark.parametrize("handler", [
    "  const { userId } = req.params;\n  if (userId !== req.session.userId) { return res.sendStatus(403); }\n  dao.getByUserId(userId);",
    "  const { userId } = req.params;\n  dao.getByUserId(userId === req.user.id ? userId : null);",
    "  const { userId } = req.params;\n  dao.getByOwner({ id: userId, owner: req.session.userId });",
    "  dao.getByUserId(req.session.userId);",                                              # the key is the session identity
    "  const name = req.query.name;\n  dao.getByName(name);",                              # not an identifier
    "  const { userId } = req.params;\n  res.send(formatId(userId));",                       # not a data lookup
])
def test_a_check_against_the_identity_or_no_client_identifier_means_no_idor(tmp_path, handler):
    assert idor(tmp_path, handler) == []


def test_role_middleware_on_the_route_is_another_layers_check(tmp_path):
    h = "  const { userId } = req.params;\n  dao.getByUserId(userId);"
    assert idor(tmp_path, h, 'app.get("/a/:userId", isLoggedIn, isAdmin, H);') == []
    assert idor(tmp_path, h, 'app.get("/a/:userId", requireRole("admin"), H);') == []
    assert len(idor(tmp_path, h, 'app.get("/a/:userId", isLoggedIn, H);')) == 1       # authentication alone is not authorisation


def test_using_the_identity_only_to_print_it_is_not_an_ownership_check(tmp_path):
    h = ('  const { id } = req.body;\n  db.User.find({ where: { id } }).then(u => {\n'
         '    res.render("x", { who: req.user.id, name: u.name });\n  });')
    assert len(idor(tmp_path, h, 'app.post("/u", H);')) == 1


def test_idor_detection_does_not_depend_on_what_the_request_is_called(tmp_path):
    a = flow.analyze(app(tmp_path, {"r.js": 'app.get("/a/:accountId", (incoming, outgoing) => {\n'
                                              '  const { accountId } = incoming.params;\n  repo.fetchAccount(accountId);\n});\n'}))
    assert len(klasses(a, "idor")) == 1


# -- missing CSRF protection -------------------------------------------------------------------------------------------

BASE = 'const express = require("express");\nconst session = require("express-session");\nconst app = express();\n'


def csrf(tmp_path, server, extra=None):
    files = {"server.js": BASE + server}
    files.update(extra or {})
    return klasses(flow.analyze(app(tmp_path, files)), "csrf-missing")


POST = 'app.use(session({ secret: "x" }));\napp.post("/t", (req, res) => { res.send("ok"); });\n'


def test_cookie_sessions_and_state_changing_routes_without_protection_are_flagged(tmp_path):
    (s,) = csrf(tmp_path, POST)
    assert s.file == "server.js" and s.line == 2 and s.confidence == "medium"            # anchored where sessions are set up
    assert s.extra["session_modules"] == ["express-session"] and s.extra["disabled_protection_in_comment"] is False
    assert s.extra["routes"] == ["POST /t"]


def test_a_commented_out_protection_call_is_the_anchor_and_raises_confidence(tmp_path):
    server = POST + '// uses csrf for forms\n/*\napp.use(csrf());\n*/\n'
    (s,) = csrf(tmp_path, server)
    assert s.line == 8 and s.confidence == "high" and s.extra["disabled_protection_in_comment"] is True   # the call, not the mention


@pytest.mark.parametrize("server", [
    'const csrf = require("csurf");\napp.use(session({ secret: "x" }));\napp.use(csrf());\napp.post("/t", (req, res) => {});\n',
    POST + 'app.use((req, res, next) => { res.locals.t = req.csrfToken(); next(); });\n',
    POST + 'app.post("/u", (req, res) => { if (req.get("X-CSRF-Token") !== req.session.t) return res.sendStatus(403); });\n',
    POST + 'const { _csrf } = req.body;\n',
    'app.use(session({ secret: "x", cookie: { sameSite: "strict" } }));\napp.post("/t", (req, res) => {});\n',
])
def test_active_protection_means_no_finding(tmp_path, server):
    assert csrf(tmp_path, server) == []


def test_a_csrf_module_that_is_imported_but_never_used_is_not_protection(tmp_path):
    assert len(csrf(tmp_path, 'const csrf = require("csurf");\n' + POST)) == 1


def test_no_finding_without_cookie_sessions(tmp_path):
    a = flow.analyze(app(tmp_path, {"server.js": 'const express = require("express");\napp.post("/t", (req, res) => {});\n'}))
    assert klasses(a, "csrf-missing") == []


def test_no_finding_without_state_changing_routes(tmp_path):
    assert csrf(tmp_path, 'app.use(session({ secret: "x" }));\napp.get("/t", (req, res) => {});\n') == []


def test_an_application_s_own_list_of_vulnerability_names_is_not_protection(tmp_path):
    """A string that merely mentions CSRF (a catalogue of weakness names) must not count as a token check."""
    assert len(csrf(tmp_path, POST, {"vulns.js": "module.exports = { ax_csrf: 'Cross-site Request Forgery' };\n"})) == 1


# -- probes for the new classes ---------------------------------------------------------------------------------------------

def xss_finding(context, raw=False):
    return {"id": "1", "klass": "xss", "evidence": {
        "context": context, "raw": raw, "tainted_fields": [["body", "name"]],
        "entry": {"route": {"method": "POST", "path": "/p"}, "request_fields": [["body", "name"], ["body", "other"]]}}}


def test_a_url_context_xss_probe_sends_a_javascript_url_and_looks_for_it_in_an_attribute():
    e, _ = probes.exploit_for(xss_finding("url-start"))
    assert e["body"] == {"name": "javascript:KVCHxss//", "other": "1"}
    assert "KVCHxss" in e["success_if"]["body_regex"] and e["success_if"]["body_regex"].startswith("=")


def test_a_raw_html_xss_probe_looks_for_unescaped_markup():
    e, _ = probes.exploit_for(xss_finding("html", raw=True))
    assert e["body"]["name"] == "kvch<b>7x7</b>" and e["success_if"]["body_regex"] == "kvch<b>7x7</b>"


def test_xss_variants_are_other_spellings_with_their_own_oracles():
    vs = probes.variants_for(xss_finding("url-start"))
    assert len(vs) == 2 and all("KVCHxss" in v["success_if"]["body_regex"] for v in vs)
    assert vs[0]["body"]["name"].lower().startswith("javascript:") and vs[1]["body"]["name"].startswith(" javascript")


@pytest.mark.parametrize("klass,ctx", [("xss", "event"), ("xss", "script"), ("xss", "css"), ("idor", ""), ("csrf-missing", "")])
def test_classes_without_a_text_oracle_say_why(klass, ctx):
    f = xss_finding(ctx) if klass == "xss" else {"id": "1", "klass": klass, "evidence": {}}
    e, reason = probes.exploit_for(f)
    assert e is None and reason


# -- the whole scan, and genericity ----------------------------------------------------------------------------------------

def test_the_scan_reports_all_three_classes_with_their_evidence(tmp_path):
    root = app(tmp_path, {
        "server.js": BASE + 'app.use(session({ secret: "x" }));\napp.get("/a/:userId", isLoggedIn, A);\n'
                           'app.post("/p", P);\nconst A = (req, res) => { const { userId } = req.params; dao.getById(userId); };\n'
                           'const P = (req, res) => { const { name } = req.body; res.render("p", { name }); };\n',
        "views/p.html": '<a href="{{name}}">x</a>'})
    found = {f.klass: f for f in static.scan(root, use_flow=True)["findings"]}
    assert {"idor", "xss", "csrf-missing"} <= set(found)
    assert found["xss"].evidence["template"] == "views/p.html" and found["xss"].evidence["context"] == "url-start"
    assert found["idor"].evidence["identifier"] == "userId" and found["csrf-missing"].evidence["state_changing_routes"] == 1
    assert "flow" in found["xss"].evidence["detected_by"]


@pytest.mark.skipif(not NODEGOAT.exists(), reason="benchmark_workspace/nodegoat not cloned")
def test_all_three_classes_survive_renaming_everything_in_the_application(tmp_path):
    """The same program with every parameter, file and function renamed must yield the same structural classes."""
    from tests.jsauto.mutate import mutate
    twin = tmp_path / "ng"
    mutate(NODEGOAT, twin)
    want = {"idor", "xss", "csrf-missing"}
    assert want <= {f.klass for f in static.scan(NODEGOAT)["findings"]}
    assert want <= {f.klass for f in static.scan(twin)["findings"]}


def test_the_new_rules_name_no_application():
    for name in ("templates.py", "flow.py"):
        text = (ROOT / "src" / "jsauto" / name).read_text().lower()
        assert "nodegoat" not in text and "dvna" not in text and "firstnamesafe" not in text
