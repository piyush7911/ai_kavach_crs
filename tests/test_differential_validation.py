from src.autonomy.differential_validation import regression_from_routes, verify_patch
from src.pyauto.probes import Route


def test_regression_from_routes_live():
    routes = [Route("GET", "/ErrorBasedSQLInjectionVulnerability/LEVEL_1"), Route("GET", "/sitemap.xml")]
    flows = regression_from_routes(routes, "http://127.0.0.1:9090/VulnerableApp")
    assert flows and all("expect" in f and "status" in f["expect"] for f in flows)
    assert all(f["method"] == "GET" for f in flows)


def test_verify_patch_proven_when_poc_dead_and_behavior_kept(monkeypatch):
    import benchmarks.oracles as O
    import src.pyauto.repair as R
    monkeypatch.setattr(O, "run_exploit", lambda b, ex: (False, "no longer fires"))      # PoC dead = fixed
    monkeypatch.setattr(R, "_flow_ok_stable", lambda b, f, tries=3: (True, "status=200"))  # behavior kept
    out = verify_patch("http://x", {"differential": {}}, [{"name": "GET /a", "expect": {"status": 200}}])
    assert out["proven"] and out["poc_fixed"] and out["behavior_preserved"]


def test_verify_patch_rejects_broken_behavior(monkeypatch):
    import benchmarks.oracles as O
    import src.pyauto.repair as R
    monkeypatch.setattr(O, "run_exploit", lambda b, ex: (False, "fixed"))
    monkeypatch.setattr(R, "_flow_ok_stable", lambda b, f, tries=3: (False, "status 500 != 200"))
    out = verify_patch("http://x", {}, [{"name": "GET /a", "expect": {"status": 200}}])
    assert out["poc_fixed"] and not out["behavior_preserved"] and not out["proven"]
