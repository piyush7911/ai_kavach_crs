"""Nuclei JSONL -> candidate Findings + route source: CWE + tag mapping, matched-at route/param."""
from benchmarks.scanners.nuclei import findings_from_nuclei, routes_from_nuclei

JSONL = (
    '{"template-id":"error-sqli","info":{"name":"Error SQLi","severity":"high",'
    '"classification":{"cwe-id":["CWE-89"]},"tags":["sqli","injection"]},'
    '"matched-at":"http://x/api/user?id=1"}\n'
    '{"template-id":"reflected-xss","info":{"name":"XSS","severity":"medium","tags":["xss"]},'
    '"matched-at":"http://x/search?q=a"}\n'
    '{"template-id":"tech-detect","info":{"name":"nginx","severity":"info","tags":["tech"]},'
    '"matched-at":"http://x/"}\n'
)


def test_findings_cwe_and_tag_mapping(tmp_path):
    p = tmp_path / "n.jsonl"
    p.write_text(JSONL)
    fs = findings_from_nuclei(p)
    by = {f.klass: f for f in fs}
    assert set(by) == {"sql-injection", "xss"}          # tech-detect has no mappable class -> dropped
    assert by["sql-injection"].evidence["param"] == "id" and by["sql-injection"].source == "nuclei"
    assert by["sql-injection"].status == "candidate"


def test_routes_from_nuclei(tmp_path):
    p = tmp_path / "n.jsonl"
    p.write_text(JSONL)
    routes = {(r.method, r.path): r.query_fields for r in routes_from_nuclei(p)}
    assert routes[("GET", "/api/user")] == ["id"] and routes[("GET", "/search")] == ["q"]
