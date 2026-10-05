"""
Further tests for the Node/JS track: the advisory snapshot builder, the CLI's choice between the offline
and registry audit, more flow-analysis cases, known gaps (marked as expected failures so they stay
visible), and the validity of the knowledge file.
"""

import json
import re
import zipfile
from pathlib import Path

import pytest

from src.jsauto import advisories as adv
from src.jsauto import flow
from src.jsauto import __main__ as cli

KNOWLEDGE = Path(__file__).resolve().parents[2] / "config" / "js_knowledge.json"


def app(tmp_path, files: dict) -> Path:
    (tmp_path / "package.json").write_text("{}")
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


# -- the advisory snapshot builder -----------------------------------------------------------------------

def _osv(id_, name, events, ecosystem="npm", withdrawn=None, sev="HIGH", cwe="CWE-79"):
    d = {"id": id_, "aliases": ["CVE-2024-1"], "summary": f"{name} problem",
         "database_specific": {"severity": sev, "cwe_ids": [cwe]},
         "affected": [{"package": {"name": name, "ecosystem": ecosystem},
                       "ranges": [{"type": "SEMVER", "events": events}]}]}
    if withdrawn:
        d["withdrawn"] = withdrawn
    return json.dumps(d)


def test_build_keeps_real_advisories_and_drops_malware_withdrawn_and_other_ecosystems(tmp_path):
    z = tmp_path / "osv.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("GHSA-aaaa.json", _osv("GHSA-aaaa", "lib-a", [{"introduced": "0"}, {"fixed": "1.2.3"}], sev="MODERATE"))
        zf.writestr("MAL-2024-1.json", _osv("MAL-2024-1", "evil-pkg", [{"introduced": "0"}]))
        zf.writestr("GHSA-gone.json", _osv("GHSA-gone", "lib-b", [{"introduced": "0"}], withdrawn="2024-01-01T00:00:00Z"))
        zf.writestr("GHSA-pypi.json", _osv("GHSA-pypi", "lib-c", [{"introduced": "0"}], ecosystem="PyPI"))
        zf.writestr("README.txt", "not an advisory")
    out = tmp_path / "npm.json.gz"
    meta = adv.build(z, out)
    snap = adv.load(out)
    assert set(snap["packages"]) == {"lib-a"} and meta["advisories"] == 1 and meta["packages"] == 1
    a = snap["packages"]["lib-a"][0]
    assert a["id"] == "GHSA-aaaa" and a["severity"] == "medium" and a["cwe"] == "CWE-79"
    assert a["ranges"] == [[{"introduced": "0"}, {"fixed": "1.2.3"}]]
    assert meta["skipped_entries"] >= 4 and len(meta["zip_sha256"]) == 64


def test_load_names_the_remedy_when_the_snapshot_is_missing(tmp_path):
    with pytest.raises(FileNotFoundError) as e:
        adv.load(tmp_path / "absent.json.gz")
    assert "build one before the event" in str(e.value)


# -- the CLI's choice of audit ------------------------------------------------------------------------------

def _run_cli(monkeypatch, tmp_path, argv):
    calls = []

    def fake_audit(root, allow_network=False, **kw):
        calls.append(allow_network)
        return {"findings": [], "error": "", "totals": {}, "mode": "registry" if allow_network else "offline"}
    monkeypatch.setattr(cli.deps, "audit", fake_audit)
    root = app(tmp_path, {"a.js": "module.exports = 1;\n"})
    rc = cli.main(["--target", str(root)] + argv)
    return rc, calls


def test_the_cli_audits_offline_by_default(monkeypatch, tmp_path):
    rc, calls = _run_cli(monkeypatch, tmp_path, [])
    assert rc == 0 and calls == [False]


def test_the_registry_audit_needs_an_explicit_flag(monkeypatch, tmp_path):
    rc, calls = _run_cli(monkeypatch, tmp_path, ["--registry-audit"])
    assert rc == 0 and calls == [True]


def test_no_deps_skips_the_audit_entirely(monkeypatch, tmp_path):
    rc, calls = _run_cli(monkeypatch, tmp_path, ["--no-deps"])
    assert rc == 0 and calls == []


def test_the_cli_refuses_a_directory_that_is_not_a_node_app(tmp_path, capsys):
    assert cli.main(["--target", str(tmp_path)]) == 2
    assert "not a Node application" in capsys.readouterr().err


# -- more flow cases ---------------------------------------------------------------------------------------

def test_new_function_with_user_data_is_a_code_injection_sink(tmp_path):
    a = flow.analyze(app(tmp_path, {"f.js": 'app.post("/f", (req, res) => { const fn = new Function(req.body.code); fn(); });\n'}))
    assert [(s.klass, s.callee) for s in a.sinks] == [("eval-injection", "new Function")]


def test_settimeout_is_a_sink_only_when_given_a_string(tmp_path):
    a = flow.analyze(app(tmp_path, {"t.js": """
app.get("/a", (req, res) => { setTimeout("run(" + req.query.x + ")", 10); });
app.get("/b", (req, res) => { setTimeout(() => res.send("ok"), parseInt(req.query.ms, 10)); });
"""}))
    assert [s.entry["route"]["path"] for s in a.sinks if s.klass == "eval-injection"] == ["/a"]


def test_reflected_output_is_reported_with_low_confidence(tmp_path):
    a = flow.analyze(app(tmp_path, {"x.js": 'app.get("/echo", (req, res) => { res.send("<p>" + req.query.q + "</p>"); });\n'}))
    (s,) = a.sinks
    assert s.klass == "reflected-output" and s.confidence == "low"        # a probe must confirm it


def test_vm_and_destructured_fs_imports_are_resolved_by_module(tmp_path):
    a = flow.analyze(app(tmp_path, {"m.js": """
const vm = require("vm");
const { readFile } = require("fs");
app.get("/v", (req, res) => { vm.runInNewContext(req.query.src); });
app.get("/r", (req, res) => { readFile(req.query.f, () => {}); });
"""}))
    assert sorted(s.klass for s in a.sinks) == ["eval-injection", "path-traversal"]


def test_a_function_name_shared_by_several_definitions_is_not_a_route_handler_by_name_alone(tmp_path):
    """`app.post('/b', h.update)` must not make an unrelated data-layer `update` an entry point."""
    a = flow.analyze(app(tmp_path, {
        "handler.js": "exports.update = (req, res) => { res.redirect(req.query.next); };\n",
        "dao.js": "exports.update = (id, value, cb) => { cb(null, id); };\n",
        "routes.js": 'app.post("/b", handlers.update);\n'}))
    entry_files = {e["file"] for e in a.entry_points}
    assert "handler.js" in entry_files and "dao.js" not in entry_files


def test_files_in_vendored_and_test_directories_are_not_analysed(tmp_path):
    bad = 'app.get("/x", (req, res) => { eval(req.query.c); });\n'
    a = flow.analyze(app(tmp_path, {"node_modules/lib/i.js": bad, "test/t.js": bad, "public/static.js": bad,
                                    "src/real.js": bad}))
    assert {s.file for s in a.sinks} == {"src/real.js"}


def test_the_request_object_passed_whole_into_a_helper_keeps_its_role(tmp_path):
    a = flow.analyze(app(tmp_path, {
        "route.js": 'const h = require("./h");\napp.get("/p", (req, res) => { h.go(req, res); });\n',
        "h.js": 'const fs = require("fs");\nexports.go = (r, s) => { fs.readFile(r.query.name, () => {}); };\n'}))
    (s,) = a.sinks
    assert s.klass == "path-traversal" and s.file == "h.js" and len(s.chain) == 2


def test_a_cycle_between_functions_terminates(tmp_path):
    a = flow.analyze(app(tmp_path, {"c.js": """
const fs = require("fs");
function ping(x) { return pong(x); }
function pong(x) { fs.readFile(x, () => {}); return ping(x); }
app.get("/c", (req, res) => { ping(req.query.x); });
"""}))
    assert [s.klass for s in a.sinks] == ["path-traversal"]


# -- known gaps, kept visible ---------------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="a renamed destructured import (`{ readFile: rf }`) is matched by its local "
                                       "name, so the module's function name is not recognised")
def test_known_gap_aliased_destructured_import(tmp_path):
    a = flow.analyze(app(tmp_path, {"g.js": 'const { readFile: rf } = require("fs");\n'
                                            'app.get("/g", (req, res) => { rf(req.query.f, () => {}); });\n'}))
    assert [s.klass for s in a.sinks] == ["path-traversal"]


@pytest.mark.xfail(strict=True, reason="chained route definitions (`router.route('/x').get(handler)`) are not "
                                       "registered, so the handler is only found by property access")
def test_known_gap_chained_route_registration(tmp_path):
    a = flow.analyze(app(tmp_path, {"g.js": 'router.route("/x").get((a, b) => { b.redirect(a.query.u); });\n'}))
    assert a.entry_points and a.entry_points[0]["via"] == "route"


# -- the knowledge file ----------------------------------------------------------------------------------------

def test_every_pattern_in_the_knowledge_file_compiles_and_every_class_has_a_severity():
    k = json.loads(KNOWLEDGE.read_text())
    patterns = list(k["sanitizers"]) + [s["callee"] for s in k["global_sinks"]] \
        + [s["methods"] for s in k["response_sinks"]] \
        + [s["functions"] for s in k["sink_modules"] if s["functions"] is not None]
    for pat in patterns:
        re.compile(pat)
    classes = {s["class"] for s in k["global_sinks"] + k["sink_modules"] + k["response_sinks"] + k["sink_keys"]}
    assert classes <= set(k["severity"]), classes - set(k["severity"])
    assert all(set(s) >= {"class", "cwe"} for s in k["global_sinks"] + k["sink_modules"] + k["sink_keys"])


def test_the_knowledge_file_names_no_application():
    text = KNOWLEDGE.read_text().lower()
    assert "nodegoat" not in text and "dvna" not in text
