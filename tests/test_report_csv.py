import csv, io
from src.jsauto.findings import Finding
from src.autonomy.report_csv import write_csv, to_rows, _HEADER


def _f(klass, sev, status="confirmed", **kw):
    return Finding(id=klass, source="x", klass=klass, file=kw.get("file", "(runtime)"),
                   status=status, severity=sev, message=f"{klass} found",
                   evidence=kw.get("evidence", {}), poc=kw.get("poc", {}), reason="observed X")


def test_header_and_confirmed_only(tmp_path):
    fs = [_f("sql-injection", "high", evidence={"route": "GET /x?id=1"}),
          _f("xss", "medium", status="candidate")]              # candidate excluded
    p = tmp_path / "r.csv"
    n = write_csv(fs, str(p))
    assert n == 1
    rows = list(csv.reader(io.StringIO(p.read_text())))
    assert rows[0] == _HEADER
    assert rows[1][1] == "SQL Injection" and rows[1][2] == "high" and rows[1][4] == "GET /x?id=1"


def test_severity_bucketing_and_order():
    fs = [_f("clickjacking", "low"), _f("command-injection", "critical"), _f("xss", "medium")]
    rows = to_rows(fs)
    assert [r[2] for r in rows] == ["critical", "med", "low"]   # sorted critical->low, medium->med
    assert rows[0][1] == "Command Injection"


def test_steps_uses_route_when_no_poc_request():
    r = to_rows([_f("ssrf", "high", evidence={"route": "GET /fetch?url=x"})])[0]
    assert "GET /fetch?url=x" in r[5] and "Observed" in r[5]
