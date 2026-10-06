"""Write-IDOR: generator builds a verify-after-write exploit for a mutating IDOR route; the oracle
confirms only when the attacker's marker appears in a read-back it did not before."""
from src.jsauto.probes import exploit_for


def _mutating_idor_finding():
    return {"klass": "idor", "evidence": {"entry": {
        "route": {"method": "POST", "path": "/benefits"},
        "request_fields": [["body", "userId"], ["body", "benefitStartDate"]]},
        "tainted_fields": [["body", "userId"]]}}


def _read_idor_finding():
    return {"klass": "idor", "evidence": {"entry": {
        "route": {"method": "GET", "path": "/allocations/:userId"},
        "request_fields": [["params", "userId"]]},
        "tainted_fields": [["params", "userId"]]}}


def test_mutating_route_builds_write_idor():
    ex, note = exploit_for(_mutating_idor_finding())
    assert "write_idor" in ex
    w = ex["write_idor"]
    assert w["write_request"]["method"] == "POST" and w["write_request"]["path"] == "/benefits"
    # the id carrier points at another user; the other field carries the marker
    assert w["write_request"]["body"]["userId"] == "2"
    assert w["write_request"]["body"]["benefitStartDate"] == w["marker"]
    assert w["read_request"] == {"method": "GET", "path": "/benefits"}


def test_read_route_still_builds_read_idor():
    ex, _ = exploit_for(_read_idor_finding())
    assert "idor" in ex and "write_idor" not in ex


def test_write_idor_oracle_confirms_on_marker_appearing(monkeypatch):
    import benchmarks.nodegoat.exploit as E
    state = {"store": ""}

    class _S:
        def __init__(self, *a, **k): pass
        def login(self, role): return True
        def request(self, method, path, headers=None, body=None):
            if method == "POST":                        # the write stores the marker
                state["store"] = (body or {}).get("benefitStartDate", "")
            return E.Response(200, f"page {state['store']}", "", "")
    monkeypatch.setattr(E, "Session", _S)
    ex = {"write_idor": {"write_request": {"method": "POST", "path": "/b", "body": {"userId": "2", "benefitStartDate": "MARK"}},
                         "read_request": {"method": "GET", "path": "/b"}, "marker": "MARK",
                         "write_as": "user", "read_as": "user"}}
    hit, detail = E.run_exploit("http://x", ex)
    assert hit is True
