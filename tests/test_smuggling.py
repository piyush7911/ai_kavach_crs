from src.pyauto.smuggling import _clte, _baseline, detect_smuggling


def test_clte_payload_has_conflicting_cl_and_te():
    p = _clte("/x", "host")
    assert b"Content-Length: 4" in p and b"Transfer-Encoding: chunked" in p and b"POST /x" in p


def test_baseline_is_well_formed():
    assert _baseline("/x", "host").startswith(b"GET /x HTTP/1.1")


def test_no_fp_on_unreachable_target():
    # nothing listening -> OSError caught -> no candidate (never a false positive)
    assert detect_smuggling("http://127.0.0.1:9") == []
