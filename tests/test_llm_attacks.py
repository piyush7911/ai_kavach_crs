"""Slice B: LLM proposes {param,class} for gap routes -> CANDIDATE findings (oracle confirms later)."""
from src.pyauto.probes import Route
from src.pyauto.llm_attacks import propose_candidates


def test_proposes_candidates_only_for_gap_routes():
    routes = [
        Route("GET", "/files"),                               # gap (no params) -> asked
        Route("GET", "/u/{id}", path_params=["id"]),          # already has a carrier -> skipped
    ]
    reply = '[{"param":"fileName","class":"path-traversal"},{"param":"redir","class":"open-redirect"},' \
            '{"param":"x","class":"business-logic"}]'         # last class not allowed -> dropped
    cands = propose_candidates(routes, lambda p: reply, lambda r: "sample body")
    got = {(f.klass, f.evidence["param"], f.evidence["route"]) for f in cands}
    assert got == {("path-traversal", "fileName", "GET /files"), ("open-redirect", "redir", "GET /files")}
    assert all(f.status == "candidate" and f.source == "llm" for f in cands)


def test_model_failure_is_tolerated():
    def boom(_):
        raise RuntimeError("down")
    assert propose_candidates([Route("GET", "/x")], boom, lambda r: "") == []
