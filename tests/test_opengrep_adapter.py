"""Opengrep adapter: parses the (Semgrep-schema) JSON into candidate Findings; param from dataflow source."""
import json
import benchmarks.scanners.opengrep as og


def test_parse_and_param(monkeypatch, tmp_path):
    rpt = {"results": [{
        "check_id": "kavach-taint-py-sqli", "path": str(tmp_path / "app.py"),
        "start": {"line": 8}, "end": {"line": 8},
        "extra": {"metadata": {"kavach_class": "sql-injection", "cwe": "CWE-89"},
                  "message": "taint", "lines": "uid = request.args.get('id')",
                  "dataflow_trace": {"taint_source": [["x", "request.args.get('id')"]]}}}]}

    class _R:
        returncode = 1
        stdout = json.dumps(rpt)
        stderr = ""
    monkeypatch.setattr(og, "_binary", lambda: "opengrep")
    monkeypatch.setattr(og.subprocess, "run", lambda *a, **k: _R())
    fs = og.findings_from_opengrep(tmp_path)
    assert len(fs) == 1
    f = fs[0]
    assert f.klass == "sql-injection" and f.source == "opengrep" and f.status == "candidate"
    assert f.evidence["param"] == "id"


def test_no_binary_returns_empty(monkeypatch):
    monkeypatch.setattr(og, "_binary", lambda: None)
    assert og.findings_from_opengrep(".") == []
