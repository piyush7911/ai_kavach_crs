"""Dynamic probe generation for a Python web target — autonomous bug DISCOVERY.

Static detection reads code and sees secrets/injections it can prove syntactically; the authz / logic
/ data-exposure classes are invisible to it (they are behaviour, not syntax). In the JS backend those are
found by dynamic probes; this is the Python counterpart.

It is route-DRIVEN, not app-specific: give it a list of `Route` (method, path, params, body/query
fields, whether auth is required) and it tries, per route, the oracle families we already have —
data exposure, boolean-injection (differential), broken object-level authorization (metamorphic),
user enumeration, mass assignment — and emits a CONFIRMED `Finding` with a replayable exploit for each
hit. The routes come from whatever the app exposes (`routes_from_openapi`, or a Flask url_map dump);
nothing here names an endpoint, so it carries to an app we never built for.

The oracles themselves are the unchanged, language-neutral ones exposed by benchmarks/oracles.py.
Every request goes through that module's global throttle, loopback only (Rules of Engagement). ReDoS /
rate-limiting are deliberately NOT probed live (that is a denial of service); they are left to review.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from benchmarks.oracles import run_exploit
from src.jsauto.findings import Finding

# field names whose presence in a response body is a data-exposure signal, and benign fillers by name
_SENSITIVE = re.compile(r'"(password|passwd|pwd|token|secret|ssn|api[_-]?key|credit[_-]?card)"', re.I)
_BENIGN = {"email": "probe@kavach.test", "password": "ProbePass1!", "book_title": "probebook",
           "secret": "x", "username": "probeuser"}
_TAUTOLOGY = "' OR '1'='1"      # boolean-injection carriers: a row-returning condition ...
_CONTRADICTION = "' OR '1'='2"  # ... and one that returns none; responses differ iff input reaches a query


@dataclass
class Route:
    method: str
    path: str                       # with {name} placeholders for path params
    path_params: list = field(default_factory=list)
    body_fields: list = field(default_factory=list)
    query_fields: list = field(default_factory=list)
    auth_required: bool = False
    operation_id: str = ""          # e.g. "api_views.users.update_password" — the route's handler


@dataclass
class ProbeCtx:
    base_url: str
    auth: dict                      # the app's auth spec (roles map etc.), as Session takes
    reseed: Optional[Callable[[], None]] = None  # reset app state between destructive probes

    @property
    def roles(self) -> dict:
        return (self.auth or {}).get("roles", {})

    def _seed(self) -> None:
        if self.reseed:
            self.reseed()


def routes_from_openapi(spec_path: str) -> list[Route]:
    """Parse an OpenAPI 3 spec into generic routes. One of several possible sources; a Flask app with
    no spec can feed the same `Route` list from its url_map instead."""
    import yaml
    spec = yaml.safe_load(open(spec_path))
    out = []
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            params = op.get("parameters", [])
            path_params = [p["name"] for p in params if p.get("in") == "path"]
            query_fields = [p["name"] for p in params if p.get("in") == "query"]
            body_fields = []
            try:
                body_fields = list(op["requestBody"]["content"]["application/json"]["schema"]["properties"])
            except (KeyError, TypeError):
                pass
            out.append(Route(method.upper(), path, path_params, body_fields, query_fields,
                             bool(op.get("security")), op.get("operationId", "")))
    return out


def route_to_source(operation_id: str) -> Optional[dict]:
    """Map a route's OpenAPI operationId to its handler location so a dynamically-found bug can be
    repaired: `api_views.users.update_password` -> {file: 'api_views/users.py', function: 'update_password'}.
    This is the bridge from HTTP-level discovery to a code-level fix; without a spec, a framework's own
    url_map gives the same (module, function)."""
    if not operation_id or "." not in operation_id:
        return None
    *module, func = operation_id.split(".")
    return {"file": "/".join(module) + ".py", "function": func}


def _benign(name: str) -> str:
    return _BENIGN.get(name, "1")


def _fill_path(path: str, values: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), _benign(m.group(1)))), path)


def _body(fields: list, override: dict | None = None) -> dict:
    override = override or {}
    return {f: override.get(f, _benign(f)) for f in fields}


def _finding(klass: str, route: Route, cwe: str, owasp: str, message: str,
             exploit: dict, detail: str, severity: str = "high") -> Finding:
    fid = f"probe:{klass}:{route.method}:{route.path}"
    src = route_to_source(route.operation_id) or {}
    return Finding(id=fid, source="probe", klass=klass, file=src.get("file", "(runtime)"),
                   function=src.get("function", ""), rule="dynamic-probe",
                   cwe=cwe, owasp=owasp, severity=severity, confidence="high",
                   message=message, status="confirmed", reason=detail,
                   evidence={"route": f"{route.method} {route.path}"}, exploit=exploit)


# --- oracle families: each takes (routes, ctx) and yields confirmed Findings -------------------------

def _data_exposure(routes, ctx):
    for r in routes:
        if r.method != "GET" or r.path_params:          # list/object reads; skip per-id reads (noisier)
            continue
        ex = {"method": "GET", "path": _fill_path(r.path, {}), "auth": ctx.auth,
              "login_as": "user" if r.auth_required else "none",
              "success_if": {"status": 200, "body_regex": _SENSITIVE.pattern}}
        hit, detail = run_exploit(ctx.base_url, ex)
        if hit:
            yield _finding("excessive-data-exposure", r, "CWE-213", "API3:2023",
                           f"{r.path} returns sensitive fields in its response", ex, detail)


def _injection(routes, ctx):
    from urllib.parse import quote
    for r in routes:
        carriers = list(r.path_params) + list(r.body_fields) + list(r.query_fields)
        if not carriers or "password" in r.body_fields:   # credential routes are input-sensitive by
            continue                                       # design (login/register) -> enumeration, not SQLi

        def build(val):
            pv = {p: quote(val, safe="") for p in r.path_params}     # payload rides in the URL -> encode
            path = _fill_path(r.path, pv)
            q = "&".join(f"{f}={quote(val, safe='')}" for f in r.query_fields)
            req = {"method": r.method, "path": path + (("?" + q) if q else "")}
            if r.body_fields:
                req["body"] = {f: val for f in r.body_fields}
            return req

        ex = {"differential": {"true_request": build(_TAUTOLOGY), "false_request": build(_CONTRADICTION)},
              "auth": ctx.auth, "login_as": "user" if r.auth_required else "none"}
        hit, detail = run_exploit(ctx.base_url, ex)
        if hit:
            yield _finding("injection", r, "CWE-89", "API8:2023",
                           f"input to {r.method} {r.path} reaches query logic (boolean-differential)",
                           ex, detail, severity="critical")


def _bola(routes, ctx):
    """Broken object-level authorization: a non-owner performs an owner-scoped action. Owner's username
    goes into the first path param; a different non-admin user attempts the same request. Served ⇒ BOLA.
    Routes whose path param is not an owner id (owner gets denied/404) self-exclude — no false positive."""
    users = [role for role, cred in ctx.roles.items() if role != "admin"]
    if len(users) < 2:
        return
    owner, other = users[0], users[1]
    owner_name = ctx.roles[owner][0]
    for r in routes:
        if not (r.auth_required and r.path_params):
            continue
        ctx._seed()
        values = {r.path_params[0]: owner_name}
        req = {"method": r.method, "path": _fill_path(r.path, values)}
        if r.body_fields:
            req["body"] = _body(r.body_fields)
        ex = {"access_control": {"request": req, "authorized": owner, "unauthorized": other},
              "auth": ctx.auth}
        hit, detail = run_exploit(ctx.base_url, ex)
        if hit:
            yield _finding("broken-object-level-auth", r, "CWE-639", "API1:2023",
                           f"a non-owner can {r.method} {r.path} for another user", ex, detail,
                           severity="critical")
    ctx._seed()


def _collection_of(path: str) -> str:
    """The collection a by-id route hangs off: /books/v1/{book_title} -> /books/v1."""
    return re.sub(r"/\{[^}]+\}$", "", path)


def _bola_setup(routes, ctx):
    """BOLA on resources that must EXIST first (books, orders, ...). The empty app has nothing to read,
    so `_bola` (which only reuses a username as the id) misses them. Here: as the owner, CREATE the
    object via the collection's POST, learn its id, then run the metamorphic read as a NON-owner. Served
    ⇒ BOLA. Generic: a by-id route `P/{id}` pairs with `POST P`; the id is the body field we posted with
    the same name, else an id in the create response."""
    users = [role for role, cred in ctx.roles.items() if role != "admin"]
    if len(users) < 2:
        return
    owner, other = users[0], users[1]
    creators = {r.path: r for r in routes
                if r.method == "POST" and not r.path_params and r.body_fields}
    for r in routes:
        base = _collection_of(r.path)
        if not (r.path_params and r.auth_required and base in creators and base != r.path):
            continue
        create = creators[base]
        id_field = r.path_params[-1]
        if id_field not in create.body_fields:    # need a deterministic id to make the exploit replayable
            continue                              # (an id minted by the server would differ each run)
        id_val = f"kavach-probe-{id_field}"
        setup = [{"method": "POST", "path": create.path, "body": _body(create.body_fields, {id_field: id_val})}]
        req = {"method": r.method, "path": _fill_path(r.path, {id_field: id_val})}
        if r.body_fields:
            req["body"] = _body(r.body_fields)
        # self-contained exploit: the create runs (as the owner) at replay time, so the repair gate can
        # reseed and still reproduce — this is the multi-step PoV support the gate needs.
        ex = {"access_control": {"setup": setup, "setup_as": owner, "request": req,
                                 "authorized": owner, "unauthorized": other}, "auth": ctx.auth}
        ctx._seed()
        hit, detail = run_exploit(ctx.base_url, ex)
        if hit:
            yield _finding("broken-object-level-auth", r, "CWE-639", "API1:2023",
                           f"a non-owner can {r.method} {r.path} after another user created it",
                           ex, detail, severity="critical")
    ctx._seed()


def _enumeration(routes, ctx):
    """User enumeration: a login route answers a known user + wrong password differently from an unknown
    user. Different ⇒ the error message distinguishes valid accounts. Identified by route shape."""
    for r in routes:
        if r.method != "POST" or "password" not in r.body_fields:
            continue
        if not re.search(r"log[_-]?in|signin|auth", r.path, re.I):
            continue
        user_field = next((f for f in r.body_fields if f != "password"), "username")
        known = ctx.roles.get("user", [ctx.roles.get("admin", ["admin"])[0]])[0]
        good_user = {"method": "POST", "path": r.path, "body": {user_field: known, "password": "wrong-xyz"}}
        bad_user = {"method": "POST", "path": r.path,
                    "body": {user_field: "nosuchuser-zzz", "password": "wrong-xyz"}}
        ex = {"differential": {"true_request": good_user, "false_request": bad_user},
              "auth": ctx.auth, "login_as": "none"}
        hit, detail = run_exploit(ctx.base_url, ex)
        if hit:
            yield _finding("user-enumeration", r, "CWE-204", "API2:2023",
                           f"{r.path} reveals whether a username exists", ex, detail, severity="medium")


def _mass_assignment(routes, ctx):
    """Mass assignment: a self-registration route honors an unspecified privileged field. Register a
    plain user and a user that also sets admin=true, then on a destructive (DELETE) route targeting a
    THIRD party, the admin-flag user is served where the plain user is denied ⇒ the extra field escalated.
    Both denied ⇒ no escalation; both served ⇒ that is BOLA, reported elsewhere, not here."""
    reg = next((r for r in routes if r.method == "POST" and "password" in r.body_fields
                and re.search(r"regist|signup|users", r.path, re.I)), None)
    privileged = next((r for r in routes if r.method == "DELETE" and r.auth_required and r.path_params), None)
    if not reg or not privileged:
        return
    victim = next((c[0] for role, c in ctx.roles.items() if role != "admin"), None)
    if not victim:
        return
    from benchmarks.oracles import Session

    def register(name, extra):
        s = Session(ctx.base_url, auth={**ctx.auth, "body_json": True})
        body = _body(reg.body_fields, {"username": name, "email": f"{name}@kavach.test"})
        body.update(extra)
        s.request("POST", reg.path, body=body)
        # log the new user in through the app's own login (reuse the auth spec's login path)
        s.auth = {**ctx.auth, "roles": {name: [name, body["password"]]}}
        return s if s.login(name) else None

    target_path = _fill_path(privileged.path, {privileged.path_params[0]: victim})

    def can_delete(sess):
        if sess is None:
            return False
        from benchmarks.oracles import _denied
        return not _denied(sess.request(privileged.method, target_path))

    ctx._seed()
    plain = can_delete(register("probeplain", {}))
    ctx._seed()
    elevated = can_delete(register("probeadmin", {"admin": True}))
    ctx._seed()
    if elevated and not plain:
        ex = {"method": reg.method, "path": reg.path, "auth": ctx.auth, "login_as": "none",
              "body": {**_body(reg.body_fields), "admin": True},
              "note": f"then {privileged.method} {privileged.path} succeeds as the new user"}
        yield _finding("mass-assignment", reg, "CWE-915", "API6:2023",
                       f"{reg.path} honors an unspecified privileged field (admin), escalating the account",
                       ex, "self-registered admin-flag user performed a privileged DELETE; a plain user could not")


_FAMILIES = [_data_exposure, _injection, _bola, _bola_setup, _enumeration, _mass_assignment]


def probe(routes: list[Route], ctx: ProbeCtx) -> list[Finding]:
    """Run every oracle family over the routes; return the confirmed findings (each with a replay)."""
    found = []
    for family in _FAMILIES:
        try:
            found.extend(family(routes, ctx))
        except Exception as e:  # noqa: BLE001 — one family failing must not sink the run
            print(f"  probe family {family.__name__} errored: {e}")
    return found
