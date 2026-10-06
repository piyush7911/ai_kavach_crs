"""Slice A: LLM-proposed routes are strictly validated into Route objects (model never bypasses checks)."""
from src.pyauto.llm_surface import propose_routes


def test_propose_routes_validates_and_builds(monkeypatch):
    reply = '''Here are the endpoints:
    ```json
    [
      {"method":"get","path":"/api/user","params":["id"]},
      {"method":"POST","path":"/login","params":["username","password"]},
      {"method":"GET","path":"/assets/app.js","params":[]},
      {"method":"GET","path":"http://evil.com/x","params":[]},
      {"method":"WEIRD","path":"/bad","params":[]},
      {"method":"GET","path":"/api/user","params":["id"]}
    ]
    ```'''
    routes = propose_routes("<html>...</html>", lambda p: reply)
    got = {(r.method, r.path): r.query_fields for r in routes}
    assert got == {("GET", "/api/user"): ["id"], ("POST", "/login"): ["password", "username"]}
    # static asset dropped, off-site dropped, bad method dropped, duplicate collapsed


def test_propose_routes_tolerates_model_failure():
    def boom(_):
        raise RuntimeError("model down")
    assert propose_routes("x", boom) == []


def test_propose_routes_handles_non_json():
    assert propose_routes("x", lambda p: "I cannot help with that.") == []
