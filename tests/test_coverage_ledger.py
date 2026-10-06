from src.autonomy.coverage_ledger import CoverageLedger, ledger_from_run
from src.pyauto.probes import Route
from src.jsauto.findings import Finding


def test_evidence_required_and_dedupe():
    L = CoverageLedger()
    assert L.record("GET /a", "sql-injection", "reported", "exploit fired") == []
    L.record("GET /a", "sql-injection", "no_issue_found", "later")      # dedupe: ignored
    assert len(L.entries()) == 1
    assert L.record("GET /b", "xxe", "not_applicable", "") != []        # evidence required
    assert L.record("GET /b", "xxe", "not_applicable", "no XML parse") == []


def test_ledger_from_run_outcomes():
    routes = [Route("GET", "/x", query_fields=["id"]), Route("GET", "/static")]
    conf = [Finding(id="1", source="probe", klass="sql-injection", file="(runtime)", status="confirmed",
                    evidence={"route": "GET /x"})]
    L = ledger_from_run(routes, conf, probe_classes=["sql-injection"])
    outs = {(e["surface"], e["outcome"]) for e in L.entries()}
    assert ("GET /x", "reported") in outs                               # confirmed -> reported
    assert ("GET /static", "needs_follow_up") in outs                   # no param -> needs_follow_up
