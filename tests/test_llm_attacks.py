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


def test_make_source_lookup_matches_by_path_segment(tmp_path):
    from src.pyauto.llm_attacks import make_source_lookup
    (tmp_path / "FooController.java").write_text('String x = queryParams.get("secretId");')
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("Foo")
    look = make_source_lookup(tmp_path)
    assert 'queryParams.get("secretId")' in look(Route("GET", "/Foo/LEVEL_1"))
    assert look(Route("GET", "/Nope/LEVEL_1")) == ""          # no match -> empty


def test_source_block_reaches_the_prompt():
    seen = {}
    def llm(prompt):
        seen["p"] = prompt
        return '[{"param":"secretId","class":"sql-injection"}]'
    cands = propose_candidates([Route("GET", "/x")], llm, lambda r: "body",
                               source_for=lambda r: 'queryParams.get("secretId")')
    assert "HANDLER SOURCE" in seen["p"] and 'queryParams.get("secretId")' in seen["p"]
    assert cands and cands[0].evidence["param"] == "secretId"
