"""Pure-logic checks for the Python dynamic probe builder — no live server.

Route parsing from an OpenAPI spec and exploit construction (path/body filling, family targeting) are
deterministic and worth a guard; the live confirmation is benchmarks/pyprobe_vampi.py against a running
VAmPI, which cannot run in CI."""
from src.pyauto.probes import (Route, _bola, _bola_setup, _collection_of, _data_exposure, _guess_body,
                               _injection, _fill_path, route_to_source, routes_from_openapi,
                               routes_from_wsgi)


def test_guess_body_from_path():
    assert _guess_body(Route("POST", "/users/v1/register")) == ["username", "password", "email"]
    assert _guess_body(Route("POST", "/users/v1/login")) == ["username", "password"]
    assert _guess_body(Route("PUT", "/users/v1/{username}/password")) == ["password"]
    assert _guess_body(Route("PUT", "/users/v1/{username}/email")) == ["email"]
    assert _guess_body(Route("GET", "/users/v1/{username}")) == []       # reads don't carry a body


def test_routes_from_wsgi_reads_url_map():
    """Spec-free introspection: method, path (converters -> {name}), path params, and the exact handler
    module/function come straight off a Werkzeug-style url_map + view_functions."""
    def handler():
        pass
    handler.__module__ = "api_views.users"
    handler.__name__ = "update_password"

    class _Rule:
        def __init__(self, rule, methods, args, endpoint):
            self.rule, self.methods, self.arguments, self.endpoint = rule, set(methods), set(args), endpoint

    class _App:
        url_map = type("M", (), {"iter_rules": lambda self: iter([
            _Rule("/users/v1/<username>/password", {"PUT", "OPTIONS"}, {"username"}, "ep1"),
            _Rule("/static/<path:filename>", {"GET"}, {"filename"}, "static"),
        ])})()
        view_functions = {"ep1": handler}

    routes = routes_from_wsgi(_App())
    assert len(routes) == 1                                  # the static endpoint is dropped
    r = routes[0]
    assert r.method == "PUT" and r.path == "/users/v1/{username}/password"
    assert r.path_params == ["username"]
    assert r.operation_id == "api_views.users.update_password"
    assert route_to_source(r.operation_id) == {"file": "api_views/users.py", "function": "update_password"}


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


def test_probe_policy_allow():
    from src.pyauto import probe_policy as P
    # DoS/ReDoS/rate-limit: never probed live (RoE)
    assert P.allow("redos", Route("GET", "/x"))[0] is False
    # data-exposure: collection reads only
    assert P.allow("excessive-data-exposure", Route("GET", "/users"))[0] is True
    assert P.allow("excessive-data-exposure", Route("GET", "/users/{id}", path_params=["id"]))[0] is False
    # injection: needs a carrier, skips credential routes
    assert P.allow("injection", Route("GET", "/u/{id}", path_params=["id"]))[0] is True
    assert P.allow("injection", Route("GET", "/health"))[0] is False
    assert P.allow("injection", Route("POST", "/login", body_fields=["username", "password"]))[0] is False
    # BOLA: authed route with a resource id
    assert P.allow("broken-object-level-auth", Route("PUT", "/u/{id}/email", path_params=["id"], auth_required=True))[0] is True
    assert P.allow("broken-object-level-auth", Route("GET", "/u/{id}", path_params=["id"], auth_required=False))[0] is False
    # enumeration: login-shaped credential POST
    assert P.allow("user-enumeration", Route("POST", "/users/v1/login", body_fields=["username", "password"]))[0] is True
    assert P.allow("user-enumeration", Route("POST", "/users/v1/register", body_fields=["username", "password"]))[0] is False


def test_routes_from_crawl_extracts_paths_and_params(monkeypatch):
    """Crawler route source: read links/forms over HTTP, collect each path + its query param names.
    Works with no framework and no spec (the hardest discovery case)."""
    import io
    import src.pyauto.probes as P
    html = ('<a href="?id=2">x</a> <a href="/login?username=&amp;password=">l</a> '
            '<a href="/users.json?callback=process">j</a> <a href="https://owasp.org/x">ext</a> '
            '<form action="/?comment=">c</form>')

    import urllib.request

    def fake_urlopen(url, timeout=0):
        return io.BytesIO(html.encode())
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    routes = {(r.method, r.path): r.query_fields for r in P.routes_from_crawl("http://x")}
    assert ("GET", "/") in routes and set(routes[("GET", "/")]) >= {"id", "comment"}
    assert routes[("GET", "/login")] == ["password", "username"]
    assert routes[("GET", "/users.json")] == ["callback"]
    assert ("GET", "/x") not in routes          # off-site owasp.org link dropped


def test_single_request_sends_only_the_carrier():
    from src.pyauto.probes import _single_request, Route
    r = Route("GET", "/x/{id}", path_params=["id"], query_fields=["a", "b"])
    # query carrier 'a' -> only a is sent (not sibling b); path id filled for routing
    req = _single_request(r, "query", "a", "PAYLOAD")
    assert "a=PAYLOAD" in req["path"] and "b=" not in req["path"]
    assert "/x/1" in req["path"]            # path param filled with benign for routing


def test_marker_family_confirms_and_pinpoints_carrier(monkeypatch):
    from src.pyauto.probes import _marker_family, Route
    import src.pyauto.probes as P
    r = Route("GET", "/", query_fields=["redir", "id"])
    # only fire when the payload rode in 'redir'
    monkeypatch.setattr(P, "run_exploit",
                        lambda base, ex: (True, "redirect") if "redir=" in ex["path"] else (False, "no"))
    found = list(_marker_family([r], _Recorder(), "open-redirect", "http://evil", {"redirect_regex": "evil"},
                                "CWE-601", "A1:2021", follow_redirects=False))
    assert len(found) == 1 and found[0].klass == "open-redirect"
    assert "redir" in found[0].message


def test_confirm_candidates_promotes_only_when_oracle_fires(monkeypatch):
    """An external-scanner candidate is promoted to confirmed ONLY if our oracle fires on its route+param;
    otherwise it stays a candidate (false-positive filtering)."""
    import src.pyauto.probes as P
    from src.jsauto.findings import Finding

    def fake_injection(routes, ctx):
        # only 'fires' for the route whose param is 'id'
        r = routes[0]
        if "id" in r.query_fields:
            yield P._finding("injection", r, "CWE-89", "A3", "x", {"differential": {}}, "true≠false", "critical")

    monkeypatch.setitem(P._CLASS_FAMILY, "sql-injection", fake_injection)
    real = Finding(id="Z1", source="zap", klass="sql-injection", file="(runtime)", status="candidate",
                   evidence={"route": "GET /u", "param": "id"})
    fp = Finding(id="Z2", source="zap", klass="sql-injection", file="(runtime)", status="candidate",
                 evidence={"route": "GET /safe", "param": "name"})
    P.confirm_candidates([real, fp], _Recorder())
    assert real.status == "confirmed" and real.exploit == {"differential": {}}
    assert fp.status == "candidate" and fp.exploit is None


def test_coverage_examined_vs_exercised():
    from src.pyauto.probes import coverage, Route
    routes = [
        Route("GET", "/users"),                               # collection read -> exercised
        Route("GET", "/u/{id}", path_params=["id"]),          # carrier -> exercised
        Route("POST", "/login", body_fields=["username", "password"]),  # login-shape -> exercised
        Route("GET", "/static/logo.png"),                     # bare GET -> data-exposure sends -> exercised
        Route("POST", "/webhook"),                            # no fields, not login -> NOT exercised
    ]
    cov = coverage(routes, [])
    assert cov["routes_examined"] == 5
    assert cov["routes_exercised"] == 4                       # 4 got a request (bare GETs + the 2 attacked)
    assert cov["routes_attacked"] == 2                        # payload sent only to /u/{id} and /login
    assert cov["attack_gap"] == 3                             # /users, /static, /webhook: no param to inject
    assert cov["attack_coverage_pct"] == 40.0


def test_xxe_family_builds_oob_xml_body(monkeypatch):
    from src.pyauto.probes import _xxe, Route
    import src.pyauto.probes as P
    sent = {}
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (sent.update(ex), (True, "oob callback received"))[1])
    found = list(_xxe([Route("GET", "/parse")], _Recorder()))
    assert sent["method"] == "POST" and sent["oob"] is True
    assert "ENTITY" in sent["body"] and sent["headers"]["Content-Type"] == "application/xml"
    assert sent["success_if"] == {"oob_marker": "{OOB_MARKER}"}
    assert found and found[0].klass == "xxe"


def test_deserialization_builds_node_serialize_oob(monkeypatch):
    from src.pyauto.probes import _deserialization, Route
    import src.pyauto.probes as P
    sent = {}
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (sent.update(ex), (True, "oob callback received"))[1])
    found = list(_deserialization([Route("POST", "/import", body_fields=["products"])], _Recorder()))
    assert sent["oob"] is True and sent["success_if"] == {"oob_marker": "{OOB_MARKER}"}
    assert "_$$ND_FUNC$$_" in sent["body"]["products"] and "{OOB_URL}" in sent["body"]["products"]
    assert found and found[0].klass == "insecure-deserialization"


def test_confirm_with_oob_payload_promotes_on_callback(monkeypatch):
    from src.pyauto.probes import confirm_with_oob_payload, ProbeCtx
    from src.jsauto.findings import Finding
    import src.pyauto.probes as P
    sent = {}
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (sent.update(ex), (True, "oob hit"))[1])
    f = Finding(id="c1", source="opengrep", klass="xxe", file="Parser.java", status="candidate",
                evidence={"route": "POST /parse"})
    n = confirm_with_oob_payload([f], ProbeCtx("http://x", auth={}),
                                 lambda route, klass: '<book><name>{OOB_URL}</name></book>')
    assert n == 1 and f.status == "confirmed"
    assert sent["oob"] is True and "{OOB_URL}" in sent["body"]
    assert sent["headers"]["Content-Type"] == "application/xml"


def test_confirm_with_oob_payload_rejects_token_less_payload(monkeypatch):
    from src.pyauto.probes import confirm_with_oob_payload, ProbeCtx
    from src.jsauto.findings import Finding
    import src.pyauto.probes as P
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (True, "should not be called"))
    f = Finding(id="c2", source="opengrep", klass="ssrf", file="x.py", status="candidate",
                evidence={"route": "POST /fetch", "param": "url"})
    n = confirm_with_oob_payload([f], ProbeCtx("http://x", auth={}),
                                 lambda route, klass: 'http://no-token-here/')  # lacks {OOB_URL}
    assert n == 0 and f.status == "candidate"           # un-confirmable -> stays candidate, no FP


def test_propose_oob_payload_requires_token():
    from src.pyauto.llm_attacks import propose_oob_payload
    from src.pyauto.probes import Route
    r = Route("POST", "/parse")
    ok = propose_oob_payload(r, "xxe", "class Book{}", "", lambda p: '<r><!ENTITY x SYSTEM "{OOB_URL}">&x;</r>')
    assert ok and "{OOB_URL}" in ok
    bad = propose_oob_payload(r, "xxe", "", "", lambda p: "<r>no token</r>")
    assert bad is None                                  # no {OOB_URL} -> rejected
    skip = propose_oob_payload(r, "sql-injection", "", "", lambda p: "' OR 1=1--")
    assert skip is None                                 # not an OOB class


def test_ssti_marker_self_validating(monkeypatch):
    from src.pyauto.probes import _ssti, Route
    import src.pyauto.probes as P
    sent = []
    monkeypatch.setattr(P, "run_exploit", lambda base, ex: (sent.append(ex), (True, "1337 in body"))[1])
    found = list(_ssti([Route("GET", "/t", query_fields=["name"])], _Recorder()))
    assert found and found[0].klass == "ssti"
    # payload carries 7*191 (not 1337); the success marker is the RESULT 1337, so an echo can't satisfy it
    val = sent[0]["path"]
    assert "7*191" in val or "7%2A191" in val
    assert sent[0]["success_if"]["body_regex"] == r"\b1337\b"
    assert len(found) == 1                                    # one confirmation per route despite many payloads


def test_data_exposure_requires_a_value_not_an_html_field():
    from src.pyauto.probes import _SENSITIVE
    assert not _SENSITIVE.search('<input name="password" class="x">')   # HTML form field: not a leak
    assert not _SENSITIVE.search('"password">Password</label>')          # HTML label
    assert _SENSITIVE.search('{"password":"hunter2"}')                   # real JSON data exposure
    assert _SENSITIVE.search('"api_key": "AKIA..."')
