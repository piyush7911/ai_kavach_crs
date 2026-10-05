"""
Node/JS detection: static scan, enclosing-function mapping, merging, dependency audit.
Offline: Semgrep uses the vendored rules, and `npm audit` is stubbed (it needs the registry).
"""

import json
import subprocess
from pathlib import Path

import pytest

from src.jsauto import deps, static

ROOT = Path(__file__).resolve().parents[2]
NODEGOAT = ROOT / "benchmark_workspace" / "nodegoat"

HANDLER = """const needle = require("needle");
function Handler() {
    this.fetchQuote = (req, res) => {
        const url = req.query.base + req.query.symbol;
        return needle.get(url, () => {});
    };
    this.compute = (req, res) => {
        const a = eval(req.body.a);
        const b = eval(req.body.b);
        return a + b;
    };
}
module.exports = Handler;
"""


@pytest.fixture
def app(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo", "dependencies": {}}))
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "h.js").write_text(HANDLER)
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "bad.js").write_text("eval(req.body.z);")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "t.js").write_text("eval(req.body.q);")
    return tmp_path


def test_function_name_comes_from_the_assignment_target():
    src = HANDLER.encode()
    assert static.enclosing_function(src, 5)[0] == "fetchQuote"      # `this.fetchQuote = (...) =>`
    assert static.enclosing_function(src, 9)[0] == "compute"
    assert static.enclosing_function(src, 1)[0] == ""                # file scope


def test_scan_finds_the_defects_names_the_function_and_skips_vendored_and_test_code(app):
    out = static.scan(app)
    by_class = {f.klass: f for f in out["findings"]}
    assert {"ssrf", "eval-injection"} <= set(by_class)
    assert by_class["ssrf"].function == "fetchQuote" and by_class["ssrf"].file == "routes/h.js"
    assert all("node_modules" not in f.file and not f.file.startswith("test/") for f in out["findings"])
    assert not out["semgrep_errors"]


def test_two_evals_in_one_function_are_one_finding_with_both_lines_kept(app):
    evals = [f for f in static.scan(app)["findings"] if f.klass == "eval-injection"]
    assert len(evals) == 1
    assert evals[0].evidence["lines"] == [8, 9] and evals[0].function == "compute"


def test_a_bcrypt_hash_is_suppressed_with_a_reason_not_dropped(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "seed.js").write_text('const u = { name: "a", hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" };\n')
    out = static.scan(tmp_path)
    assert not out["findings"] and out["suppressed"] and out["suppressed"][0].reason


# -- dependency audit (npm stubbed) ------------------------------------------------------------------

AUDIT = {"vulnerabilities": {
    "express": {"isDirect": True, "severity": "high", "range": "<=4.21.2",
                "via": [{"title": "Open Redirect in malformed URLs", "cwe": ["CWE-601"]}],
                "fixAvailable": {"name": "express", "version": "4.22.0", "isSemVerMajor": False}},
    "cookie": {"isDirect": False, "severity": "low", "range": "<0.7", "via": [{"title": "x"}], "fixAvailable": True}},
    "metadata": {"vulnerabilities": {"total": 2}}}


def _stub_npm(monkeypatch, stdout, code=0):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, code, stdout=stdout, stderr="")
    monkeypatch.setattr(deps.subprocess, "run", fake_run)


def _pkg(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(json.dumps(
        {"packages": {"node_modules/express": {"version": "4.16.4"}}}))
    return tmp_path


def test_only_direct_runtime_dependencies_become_findings(tmp_path, monkeypatch):
    _stub_npm(monkeypatch, json.dumps(AUDIT))
    out = deps.audit(_pkg(tmp_path))
    assert [f.evidence["package"] for f in out["findings"]] == ["express"]
    f = out["findings"][0]
    assert f.evidence["installed"] == "4.16.4" and f.evidence["fix_version"] == "4.22.0"
    assert f.evidence["fix_is_major_bump"] is False and f.severity == "high"


def test_a_failed_audit_is_an_error_never_an_empty_clean_result(tmp_path, monkeypatch):
    _stub_npm(monkeypatch, json.dumps({"error": {"summary": "request to registry failed, reason: ENOTFOUND"}}))
    out = deps.audit(_pkg(tmp_path))
    assert out["findings"] == [] and "ENOTFOUND" in out["error"]
    _stub_npm(monkeypatch, "not json")
    assert deps.audit(_pkg(tmp_path))["error"]


def test_no_lockfile_is_reported_not_treated_as_clean(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    assert "no package-lock.json" in deps.audit(tmp_path)["error"]


# -- smoke test on the real benchmark target (skipped if it is not cloned) ----------------------------

@pytest.mark.skipif(not NODEGOAT.exists(), reason="benchmark_workspace/nodegoat not cloned")
def test_nodegoat_detection_smoke():
    classes = {f.klass for f in static.scan(NODEGOAT)["findings"]}
    assert {"eval-injection", "ssrf", "nosql-injection", "open-redirect", "redos",
            "hardcoded-secret", "private-key-in-repo"} <= classes


# -- genericity: nothing may depend on the names of the application it was developed against --------

def test_detection_survives_renaming_the_request_parameter_files_and_functions(tmp_path):
    """Same program, different spelling. A rule keyed on `req` or on a file name fails here."""
    import re
    app = tmp_path / "orig"
    (app / "routes").mkdir(parents=True)
    (app / "package.json").write_text("{}")
    (app / "routes" / "quotes.js").write_text(HANDLER)
    base = {f.klass for f in static.scan(app)["findings"]}
    assert {"ssrf", "eval-injection"} <= base

    twin = tmp_path / "twin"
    (twin / "lib").mkdir(parents=True)
    (twin / "package.json").write_text("{}")
    text = re.sub(r"\breq\b", "incomingMsg", HANDLER)
    text = re.sub(r"\bres\b", "outgoingMsg", text).replace("fetchQuote", "zq").replace("compute", "yw")
    (twin / "lib" / "zz.js").write_text(text)
    assert {f.klass for f in static.scan(twin)["findings"]} == base


@pytest.mark.skipif(not NODEGOAT.exists(), reason="benchmark_workspace/nodegoat not cloned")
def test_nodegoat_detection_is_unchanged_when_every_name_in_it_is_changed(tmp_path):
    from tests.jsauto.mutate import mutate
    twin = tmp_path / "ng"
    mutate(NODEGOAT, twin)
    original = {f.klass for f in static.scan(NODEGOAT)["findings"]}
    assert {f.klass for f in static.scan(twin)["findings"]} == original


def test_no_engine_file_names_the_benchmark_target():
    """
    A tripwire, not a proof: engine code, rules and the dashboard must not mention the benchmark
    application or its function names. Tests, plans and docs may; they describe it.
    """
    import re
    forbidden = ("nodegoat", "owasp-nodejs-goat", "allocations-dao", "handlecontributionsupdate",
                 "displayresearch", "searchcriteria", "handleprofileupdate", "retirement")
    offenders = []
    for base in (ROOT / "src", ROOT / "config", ROOT / "dashboard"):
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in (".py", ".yaml", ".yml", ".js", ".html", ".json", ".sh"):
                continue
            if "__pycache__" in path.parts or "uploads" in path.parts or "runs" in path.parts:
                continue
            # reference URLs in vendored rule metadata are not logic; everything else is checked
            text = re.sub(r"https?://\S+", "", path.read_text(errors="replace")).lower()
            offenders += [f"{path.relative_to(ROOT)}: {w}" for w in forbidden if w in text]
    assert not offenders, offenders
