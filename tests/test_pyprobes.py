"""Pure-logic checks for the Python dynamic probe builder — no live server.

Route parsing from an OpenAPI spec and exploit construction (path/body filling, family targeting) are
deterministic and worth a guard; the live confirmation is benchmarks/pyprobe_vampi.py against a running
VAmPI, which cannot run in CI."""
from src.pyauto.probes import (Route, _bola, _bola_setup, _collection_of, _data_exposure,
                               _injection, _fill_path, route_to_source, routes_from_openapi)


def test_route_to_source_maps_operation_id():
    assert route_to_source("api_views.users.update_password") == {
        "file": "api_views/users.py", "function": "update_password"}
    assert route_to_source("") is None
    assert route_to_source("nodots") is None


def test_openapi_parse():
    routes = routes_from_openapi("benchmark_workspace/VAmPI/openapi_specs/openapi3.yml")
    by = {(r.method, r.path): r for r in routes}
    assert ("GET", "/users/v1/{username}") in by
    assert ("POST", "/users/v1/register") in by
    reg = by[("POST", "/users/v1/register")]
    assert set(reg.body_fields) == {"username", "password", "email"}
    assert by[("PUT", "/users/v1/{username}/password")].auth_required
    assert not by[("GET", "/users/v1/{username}")].auth_required
    assert by[("GET", "/users/v1/{username}")].path_params == ["username"]


def test_fill_path():
    assert _fill_path("/users/v1/{username}/email", {"username": "name1"}) == "/users/v1/name1/email"
    # unknown param gets a benign filler, not left as a placeholder
    assert "{" not in _fill_path("/books/v1/{book_title}", {})


class _Recorder:
    """A ctx-like double that records the exploits a family builds instead of sending them."""
    def __init__(self, hit=False):
        self.base_url = "http://x"
        self.auth = {"roles": {"user": ["name1", "p"], "user2": ["name2", "p"], "admin": ["admin", "p"]}}
        self.sent = []
        self._hit = hit

    @property
    def roles(self):
        return self.auth["roles"]

    def _seed(self):
        pass


def _run(family, routes, monkeypatch, hit=True):
    rec = _Recorder()
    import src.pyauto.probes as P
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (hit, "ok") if rec.sent.append(ex) or True else (hit, "ok"))
    found = list(family(routes, rec))
    return rec.sent, found


def test_injection_builds_differential_on_path_param(monkeypatch):
    r = Route("GET", "/users/v1/{username}", path_params=["username"])
    sent, found = _run(_injection, [r], monkeypatch, hit=True)
    ex = sent[0]
    assert "differential" in ex
    # the payload rides in the URL path, so it is percent-encoded (quote(... safe=""))
    from urllib.parse import unquote
    assert "OR '1'='1" in unquote(ex["differential"]["true_request"]["path"])
    assert "OR '1'='2" in unquote(ex["differential"]["false_request"]["path"])
    assert found and found[0].klass == "injection" and found[0].status == "confirmed"


def test_data_exposure_skips_per_id_reads(monkeypatch):
    routes = [Route("GET", "/users/v1"), Route("GET", "/users/v1/{username}", path_params=["username"])]
    sent, _ = _run(_data_exposure, routes, monkeypatch, hit=False)
    assert [e["path"] for e in sent] == ["/users/v1"]   # only the collection read is probed


def test_bola_targets_owner_vs_other(monkeypatch):
    r = Route("PUT", "/users/v1/{username}/password", path_params=["username"],
              body_fields=["password"], auth_required=True)
    sent, found = _run(_bola, [r], monkeypatch, hit=True)
    ac = sent[0]["access_control"]
    assert ac["request"]["path"] == "/users/v1/name1/password"   # owner's name substituted
    assert ac["authorized"] == "user" and ac["unauthorized"] == "user2"
    assert found[0].klass == "broken-object-level-auth"


def test_collection_of():
    assert _collection_of("/books/v1/{book_title}") == "/books/v1"
    assert _collection_of("/books/v1") == "/books/v1"


def test_bola_setup_emits_self_contained_exploit(monkeypatch):
    """The by-id read pairs with the collection POST; the emitted exploit carries the create as a `setup`
    step (run as the owner at replay time) so the repair gate can reseed and still reproduce it."""
    routes = [Route("POST", "/books/v1", body_fields=["book_title", "secret"], auth_required=True),
              Route("GET", "/books/v1/{book_title}", path_params=["book_title"], auth_required=True)]
    import src.pyauto.probes as P
    sent = []
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (sent.append(ex), (True, "ok"))[1])
    found = list(_bola_setup(routes, _Recorder()))
    ac = sent[0]["access_control"]
    assert ac["setup"][0]["method"] == "POST" and ac["setup"][0]["path"] == "/books/v1"
    assert ac["setup"][0]["body"]["book_title"] == "kavach-probe-book_title"
    assert ac["setup_as"] == "user"
    assert ac["request"]["path"] == "/books/v1/kavach-probe-book_title"
    assert found[0].klass == "broken-object-level-auth"
