"""ZAP report -> candidate Findings: CWE/name mapping, route+param capture, both JSON shapes."""
import json
from benchmarks.scanners.zap import findings_from_zap


def test_zap_site_shape(tmp_path):
    rpt = {"site": [{"@name": "http://x", "alerts": [
        {"alert": "SQL Injection", "cweid": "89", "riskcode": "3",
         "instances": [{"uri": "http://x/users?id=1", "method": "GET", "param": "id"}]},
        {"alert": "Cloud Metadata Potentially Exposed", "cweid": "0", "riskcode": "2", "instances": [{"uri": "http://x/"}]},
    ]}]}
    p = tmp_path / "zap.json"
    p.write_text(json.dumps(rpt))
    fs = findings_from_zap(p)
    by = {f.klass: f for f in fs}
    assert "sql-injection" in by                      # CWE-89 mapped
    assert by["sql-injection"].evidence["param"] == "id"
    assert by["sql-injection"].evidence["route"] == "GET /users"
    assert by["sql-injection"].status == "candidate" and by["sql-injection"].source == "zap"
    assert len(fs) == 1                               # the unmapped 'Cloud Metadata' alert is dropped


def test_zap_name_fallback_when_no_cwe(tmp_path):
    rpt = {"alerts": [{"name": "Cross Site Scripting (Reflected)", "cweid": "0", "riskcode": "2",
                       "instances": [{"url": "http://x/s?q=1", "method": "GET", "param": "q"}]}]}
    p = tmp_path / "z.json"
    p.write_text(json.dumps(rpt))
    fs = findings_from_zap(p)
    assert len(fs) == 1 and fs[0].klass == "xss" and fs[0].evidence["param"] == "q"


def test_routes_from_zap_as_route_source(tmp_path):
    """ZAP instances become Routes (method, path, params) — a discovery source that hands us param names."""
    import json
    from benchmarks.scanners.zap import routes_from_zap
    rpt = {"site": [{"alerts": [
        {"alert": "SQL Injection", "cweid": "89", "instances": [
            {"uri": "http://x/api/user?id=1", "method": "GET", "param": "id"}]},
        {"alert": "X", "cweid": "0", "instances": [
            {"uri": "http://x/api/search?q=a&lang=en", "method": "GET"}]},
    ]}]}
    p = tmp_path / "z.json"
    p.write_text(json.dumps(rpt))
    routes = {(r.method, r.path): r.query_fields for r in routes_from_zap(p)}
    assert routes[("GET", "/api/user")] == ["id"]
    assert set(routes[("GET", "/api/search")]) == {"q", "lang"}
