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
from src.jsauto.findings import apply_security, Finding
from src.pyauto import probe_policy

# field names whose presence in a response body is a data-exposure signal, and benign fillers by name
_SENSITIVE = re.compile(r'"(password|passwd|pwd|token|secret|ssn|api[_-]?key|credit[_-]?card)"', re.I)
_BENIGN = {"email": "probe@kavach.test", "password": "ProbePass1!", "book_title": "probebook",
           "secret": "x", "username": "probeuser"}
# Boolean-injection payload styles: (always-true, always-false). The oracle confirms if the two answers
# differ. Different quoting contexts need different payloads, so we try each style: string/quoted (input
# sits inside '...') and numeric (input sits bare after `=`). One style alone misses the other context.
_INJECTION_STYLES = [
    ("' OR '1'='1", "' OR '1'='2"),   # string context:  WHERE x = '<input>'
    ("1 OR 1=1", "1 OR 1=2"),         # numeric context, list result: all rows vs one
    ("0 OR 1=1", "0 OR 1=2"),         # numeric, single-row + existing base id: present vs absent (flips)
    # both pairs differ ONLY in a trailing digit, which `_norm` strips — so if the endpoint merely
    # reflects the payload the two responses still normalise equal (no false positive); a real query
    # returns different rows (all vs one), which survives normalisation.
]


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


_FRAMEWORK_MODULES = ("connexion", "flask", "werkzeug", "swagger_ui", "flask_cors")
_CREDENTIAL_BODY = {r"regist|signup": ["username", "password", "email"],
                    r"log[_-]?in|signin|auth": ["username", "password"]}


def routes_from_wsgi(app) -> list[Route]:
    """Discover routes from a LIVE WSGI app — no spec needed. Reads the Flask/Werkzeug url_map and the
    bound view function, which gives method, path, path params AND the exact handler module/function
    (so repair still knows what to fix). Body/query fields are not declared by the url_map, so they are
    left empty and filled dynamically by `enrich_routes`. This is the spec-free source for an app we
    were handed with no OpenAPI: a plain Flask app, or any framework whose url_map we can read."""
    flask_app = getattr(app, "app", app)        # connexion.FlaskApp -> underlying Flask
    out = []
    for rule in flask_app.url_map.iter_rules():
        fn = flask_app.view_functions.get(rule.endpoint)
        module = getattr(fn, "__module__", "") or ""
        if rule.endpoint == "static" or module.split(".")[0] in _FRAMEWORK_MODULES:
            continue                            # skip framework-internal endpoints (static, swagger, ...)
        path = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", rule.rule)   # <int:id> / <name> -> {id}/{name}
        op_id = f"{module}.{getattr(fn, '__name__', '')}" if module else ""
        for method in sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS")):
            out.append(Route(method, path, sorted(rule.arguments), [], [], False, op_id))
    return out


def _guess_body(route: Route) -> list:
    """Body fields a bare url_map does not declare, guessed from the path. Login/register get the usual
    credential fields; a PUT/PATCH like `.../password` or `.../email` gets the field its last path
    segment names (so the request is well-formed enough to reach the handler, not bounced by validation)."""
    for pattern, fields in _CREDENTIAL_BODY.items():
        if re.search(pattern, route.path, re.I):
            return list(fields)
    if route.method in ("PUT", "PATCH"):
        last = route.path.rstrip("/").split("/")[-1]
        if last and "{" not in last:
            return [last]
    return []


def enrich_routes(routes: list[Route], ctx: "ProbeCtx") -> list[Route]:
    """Fill the gaps a bare url_map leaves, so the oracle families fire without a spec:
      * request bodies are guessed from the path (`_guess_body`), so enumeration/mass-assignment have
        fields to send, injection knows to skip credential routes, and PUT/PATCH reach their handler;
      * auth_required is inferred by a metamorphic probe — if an anonymous request is refused but a
        logged-in user is served the same request, the route is auth-protected. This differential is
        robust to frameworks that answer a missing token with 400 (connexion) rather than 401, and it
        does NOT flag a genuinely public route (served to anon too). Loopback + throttled (RoE)."""
    from benchmarks.oracles import Session
    # try the most-privileged role first: an admin-only route denies a plain user too, so a non-admin
    # probe would wrongly read it as public.
    roles = sorted(ctx.roles, key=lambda x: x != "admin")
    for r in routes:
        if not r.body_fields:
            r.body_fields = _guess_body(r)
        if r.auth_required:
            continue
        path = _fill_path(r.path, {})
        body = _body(r.body_fields) if r.body_fields else None
        anon = Session(ctx.base_url, auth={**ctx.auth, "body_json": True}).request(r.method, path, body=body)
        if anon.status < 400 or anon.status == 404:
            continue                            # served (or genuine not-found) anonymously -> public
        for role in roles:                      # any role served where anon was refused ⇒ auth-protected
            s = Session(ctx.base_url, auth={**ctx.auth, "body_json": True})
            s.login(role)
            authed = s.request(r.method, path, body=body)
            if authed.status < 400 or authed.status != anon.status:
                r.auth_required = True
                break
    return routes


def routes_from_crawl(base_url: str, seeds: tuple = ("/",), max_pages: int = 25) -> list[Route]:
    """Discover routes with NEITHER a spec NOR a framework to introspect — the hardest case (e.g. a raw
    HTTP handler). Fetch pages over HTTP, read the links/forms, and collect each path plus the query/form
    field names it uses. Works on any app that links its own endpoints; purely HTTP, so it needs nothing
    installed and no source. (This is the third route source, after OpenAPI and a live url_map.)"""
    import html as _html
    import urllib.parse
    import urllib.request
    link = re.compile(r'(?:href|action)\s*=\s*["\']([^"\']+)["\']', re.I)
    base = base_url.rstrip("/")
    host = urllib.parse.urlparse(base).netloc
    seen: set = set()
    queue = list(seeds)
    routes: dict = {}                                   # (method, path) -> set(param names)
    while queue and len(seen) < max_pages:
        page = queue.pop(0)
        if page in seen:
            continue
        seen.add(page)
        page_url = base + page
        try:
            body = urllib.request.urlopen(page_url, timeout=5).read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            continue
        for raw in link.findall(body):
            u = _html.unescape(raw)
            if u.startswith(("mailto:", "javascript:", "#", "data:")):
                continue
            absolute = urllib.parse.urljoin(page_url, u)     # resolve relative links against this page
            parsed = urllib.parse.urlparse(absolute)
            if parsed.scheme not in ("http", "https") or parsed.netloc != host:   # off-site / non-http
                continue
            path = parsed.path or "/"
            params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
            routes.setdefault(("GET", path), set()).update(params)
            if not parsed.query and path not in seen:       # crawl plain pages a little further
                queue.append(path)
    return [Route(m, p, query_fields=sorted(ps)) for (m, p), ps in sorted(routes.items())]


def routes_from_sitemap(sitemap_url: str) -> list[Route]:
    """Routes from a standard sitemap.xml (`<loc>` entries). Many apps ship one, and a SPA that hides its
    endpoints from a link crawl often still lists them here. Paths are origin-absolute; params (if any in
    the URL) are collected, but sitemaps usually carry none — that's what `mine_params` is for."""
    import urllib.parse
    import urllib.request
    try:
        body = urllib.request.urlopen(sitemap_url, timeout=5).read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return []
    routes: dict = {}
    for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", body, re.S | re.I):
        p = urllib.parse.urlparse(loc.strip())
        path = p.path or "/"
        params = list(urllib.parse.parse_qs(p.query, keep_blank_values=True).keys())
        routes.setdefault(("GET", path), set()).update(params)
    return [Route(m, p, query_fields=sorted(ps)) for (m, p), ps in sorted(routes.items())]


# High-signal query-parameter names, for apps that expose neither a spec nor forms (the name is the only
# thing standing between us and the vulnerable code path). Ordered by how commonly they carry a bug.
_PARAM_WORDS = ["id", "userId", "user", "name", "url", "uri", "redirect", "returnUrl", "return", "next",
                "dest", "target", "file", "fileName", "filename", "path", "cmd", "command", "q", "query",
                "search", "input", "data", "page", "dir", "host", "domain", "xml", "callback", "image"]


def _norm_body(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\d+", "", s)).strip()


def mine_params(base_url: str, routes: list[Route], ctx: "ProbeCtx",
                words: list = None, budget: int = 4000) -> list[Route]:
    """Discover which query parameters a route actually reads, when they're exposed nowhere (SPA + JSON API,
    no forms). For each route: take a no-param baseline, then add one candidate name at a time; if the
    response changes, the route reads that parameter. Bounded by `budget` requests; loopback + throttled."""
    from benchmarks.oracles import Session
    words = words or _PARAM_WORDS
    spent = 0

    def signature(resp):
        # a read parameter can change ANY of these — body (data), status/Location (redirects, errors),
        # length (a file read vs a not-found). Comparing only the body misses redirect/traversal params.
        return (resp.status, resp.location, _norm_body(resp.body), len(resp.body) // 16)

    for r in routes:
        if r.query_fields or r.path_params or spent >= budget:
            continue
        s = Session(base_url, auth=ctx.auth)
        if not s.login("user" if r.auth_required else "none"):
            continue
        base = signature(s.request(r.method, r.path))
        live = []
        for w in words:
            if spent >= budget:
                break
            sep = "&" if "?" in r.path else "?"
            for val in ("1", "kvchP9z"):                   # an existing id, and a reflective token
                spent += 1
                resp = s.request(r.method, f"{r.path}{sep}{w}={val}")
                if signature(resp) != base or "kvchP9z" in resp.body:   # changed output OR reflected us
                    live.append(w)
                    break
        r.query_fields = live
    return routes


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
    f = Finding(id=fid, source="probe", klass=klass, file=src.get("file", "(runtime)"),
                function=src.get("function", ""), rule="dynamic-probe",
                cwe=cwe, owasp=owasp, severity=severity, confidence="high",
                message=message, status="confirmed", reason=detail,
                evidence={"route": f"{route.method} {route.path}"}, exploit=exploit)
    return apply_security(f, "AUTHENTICATED" if route.auth_required else "EXTERNAL", detail)


# --- oracle families: each takes (routes, ctx) and yields confirmed Findings -------------------------

def _data_exposure(routes, ctx):
    for r in routes:
        if not probe_policy.allow("excessive-data-exposure", r)[0]:   # collection reads only (policy)
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
        if not probe_policy.allow("injection", r)[0]:      # needs a carrier; skips credential routes (policy)
            continue

        def build(val):
            pv = {p: quote(val, safe="") for p in r.path_params}     # payload rides in the URL -> encode
            path = _fill_path(r.path, pv)
            q = "&".join(f"{f}={quote(val, safe='')}" for f in r.query_fields)
            req = {"method": r.method, "path": path + (("?" + q) if q else "")}
            if r.body_fields:
                req["body"] = {f: val for f in r.body_fields}
            return req

        # Try each payload STYLE: a string/quoted context ('...' OR '1'='1) and a numeric context
        # (1 OR 1=1). The same bug lives behind different quoting, so a single style misses half of them
        # (e.g. a numeric `WHERE id=<input>` is untouched by a quote-based payload). Confirm on first hit.
        for true_val, false_val in _INJECTION_STYLES:
            ex = {"differential": {"true_request": build(true_val), "false_request": build(false_val)},
                  "auth": ctx.auth, "login_as": "user" if r.auth_required else "none"}
            hit, detail = run_exploit(ctx.base_url, ex)
            if hit:
                yield _finding("injection", r, "CWE-89", "API8:2023",
                               f"input to {r.method} {r.path} reaches query logic (boolean-differential)",
                               ex, detail, severity="critical")
                break


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
        if not probe_policy.allow("broken-object-level-auth", r)[0]:   # authed route with a resource id (policy)
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
        if not probe_policy.allow("user-enumeration", r)[0]:   # login-shaped credential POST (policy)
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


# --- single-request marker families (ported from the JS probe set) --------------------------------------
# Each injects a payload into one carrier at a time and judges by a self-validating marker, so a merely
# reflected input never false-positives: open-redirect checks the Location header (not the body);
# command-injection's marker (31338) is the RESULT of a command, absent from the payload (31337);
# path-traversal looks for /etc/passwd's structure; XSS requires the tag to come back UN-escaped; SSRF is
# an out-of-band callback to our own listener. Payloads mirror config/js_probes.json.

def _single_request(route: Route, loc: str, name: str, value: str) -> dict:
    """Send ONLY the carrier under test (plus path params needed for routing) — not benign siblings. Apps
    that dispatch on "which param is present" (e.g. a raw handler) only reach the vulnerable branch when
    the sibling params are absent; a single-field payload is also enough for these one-field bug classes."""
    from urllib.parse import quote, urlencode
    # path-param values go straight into the URL path, so encode them (a cmdi/traversal payload has spaces
    # and slashes); keep {OOB_URL}/{OOB_MARKER} braces literal for the runner to substitute.
    pv = {p: (quote(value, safe="{}") if (loc == "path" and p == name) else _benign(p))
          for p in route.path_params}
    path = _fill_path(route.path, pv)
    if loc == "query":
        path += ("&" if "?" in path else "?") + urlencode({name: value}, quote_via=quote, safe="{}")
    req = {"method": route.method, "path": path}
    if loc == "body":
        req["body"] = {name: value}
        req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
    return req


def _marker_family(routes, ctx, klass, value, success_if, cwe, owasp, *,
                   oob=False, follow_redirects=None, severity="high"):
    for r in routes:
        if not probe_policy.allow(klass, r)[0]:
            continue
        carriers = ([("path", p) for p in r.path_params] + [("query", q) for q in r.query_fields]
                    + [("body", b) for b in r.body_fields])
        for loc, name in carriers:
            ex = _single_request(r, loc, name, value)
            ex.update(success_if={**success_if}, auth=ctx.auth,
                      login_as="user" if r.auth_required else "none")
            if oob:
                ex["oob"] = True
            if follow_redirects is not None:
                ex["follow_redirects"] = follow_redirects
            hit, detail = run_exploit(ctx.base_url, ex)
            if hit:
                yield _finding(klass, r, cwe, owasp,
                               f"{klass} via {loc} field {name!r} on {r.method} {r.path}", ex, detail, severity)
                break                                   # one carrier is enough to prove the route


_REDIRECT_RE = (r"(?i)^\s*(?:(?:https?:)?[/\\]{2}|https?:[/\\]*|/[\t\r\n]+[/\\])"
                r"(?:[^/\\@]*@)?kavach-probe\.invalid(?:[:/\\?#]|$)")


def _open_redirect(routes, ctx):
    yield from _marker_family(routes, ctx, "open-redirect", "https://kavach-probe.invalid/landing",
                              {"redirect_regex": _REDIRECT_RE}, "CWE-601", "A1:2021",
                              follow_redirects=False, severity="medium")


def _ssrf(routes, ctx):
    yield from _marker_family(routes, ctx, "ssrf", "{OOB_URL}", {"oob_marker": "{OOB_MARKER}"},
                              "CWE-918", "A10:2021", oob=True, severity="high")


def _command_injection(routes, ctx):
    yield from _marker_family(routes, ctx, "command-injection", ";expr 31337 + 1", {"body_regex": "31338"},
                              "CWE-78", "A3:2021", severity="critical")


def _path_traversal(routes, ctx):
    yield from _marker_family(routes, ctx, "path-traversal", "../../../../../../etc/passwd",
                              {"body_regex": r"root:[^\n]*:0:0"}, "CWE-22", "A1:2021", severity="high")


def _reflected_xss(routes, ctx):
    yield from _marker_family(routes, ctx, "xss", "kvch<b>7x7</b>",
                              {"body_regex": "kvch<b>7x7</b>", "require_html": True},
                              "CWE-79", "A3:2021", severity="medium")


_FAMILIES = [_data_exposure, _injection, _bola, _bola_setup, _enumeration, _mass_assignment,
             _open_redirect, _ssrf, _command_injection, _path_traversal, _reflected_xss]

# which oracle family confirms a given class — used to re-test an EXTERNAL scanner's alert (ZAP/Nuclei)
# on its own route+param, turning its "maybe" into our proven/dropped.
_CLASS_FAMILY = {
    "sql-injection": _injection, "nosql-injection": _injection, "injection": _injection,
    "xss": _reflected_xss, "command-injection": _command_injection, "path-traversal": _path_traversal,
    "ssrf": _ssrf, "open-redirect": _open_redirect,
}


def confirm_candidates(findings: list[Finding], ctx: ProbeCtx) -> list[Finding]:
    """Re-test each CANDIDATE finding (e.g. from a ZAP/Nuclei report) with our own oracle on the exact
    route + parameter it names: build a one-route probe for the matching family and, if it fires, promote
    the candidate to `confirmed` with the replayable exploit attached. This is how an external scanner's
    breadth becomes our proof — its false positives simply never confirm. Findings without a usable
    route/param, or a class we have no oracle for, are left as candidates."""
    for f in findings:
        if f.status == "confirmed":
            continue
        family = _CLASS_FAMILY.get(f.klass)
        ev = f.evidence or {}
        route_str, param = ev.get("route", ""), ev.get("param")
        if not family or not route_str:
            continue
        method, _, path = route_str.partition(" ")
        method = method or "GET"
        carrier = {"query_fields": [param]} if param and method == "GET" else (
            {"body_fields": [param]} if param else {})
        r = Route(method, path or "/", **carrier)
        for hit in family([r], ctx):                 # the family yields a confirmed Finding if it fires
            f.status = "confirmed"
            f.exploit, f.reason = hit.exploit, hit.reason
            f.stride, f.cvss = hit.stride, hit.cvss
            f.reachability, f.exploitability, f.poc = hit.reachability, hit.exploitability, hit.poc
            break
    return findings


def probe(routes: list[Route], ctx: ProbeCtx) -> list[Finding]:
    """Run every oracle family over the routes; return the confirmed findings (each with a replay)."""
    _log_exclusions(routes)
    found = []
    for family in _FAMILIES:
        try:
            found.extend(family(routes, ctx))
        except Exception as e:  # noqa: BLE001 — one family failing must not sink the run
            print(f"  probe family {family.__name__} errored: {e}")
    return found


def _is_exercised(r: Route) -> bool:
    """Does at least one oracle family send a request to this route? (A route with no carrier and no
    collection-read shape is 'examined but not exercised' — surface we saw but could not attack.)"""
    has_carrier = bool(r.path_params or r.query_fields or r.body_fields)
    is_collection_read = r.method == "GET" and not r.path_params        # data-exposure target
    import re as _re
    is_login = r.method == "POST" and "password" in r.body_fields and bool(_re.search(r"log[_-]?in|signin|auth", r.path, _re.I))
    return has_carrier or is_collection_read or is_login


def coverage(routes: list[Route], findings: list = None) -> dict:
    """Honest coverage of a dynamic run: how much surface we SAW vs actually EXERCISED (sent a request to)
    vs CONFIRMED. 'Zero findings is never safe' — a big unexercised gap means the surface out-ran our
    probes (the signal that should trigger the LLM fallback), not that the app is clean."""
    findings = findings or []
    examined = len(routes)
    exercised = [r for r in routes if _is_exercised(r)]
    confirmed_routes = {f.evidence.get("route") for f in findings if getattr(f, "status", "") == "confirmed"}
    return {
        "routes_examined": examined,
        "routes_exercised": len(exercised),
        "routes_unexercised": examined - len(exercised),   # surface seen but not attacked = the gap
        "routes_confirmed_a_bug": len(confirmed_routes),
        "coverage_pct": round(100 * len(exercised) / examined, 1) if examined else 0.0,
    }


def _log_exclusions(routes: list[Route]) -> None:
    """Audit line: how many (route, class) pairs the pre-probe policy skips, so no live request is spent
    on them. Satisfies the RoE's 'keep a record of what was and was not probed'."""
    klasses = ("excessive-data-exposure", "injection", "broken-object-level-auth", "user-enumeration")
    skipped = sum(1 for r in routes for k in klasses if not probe_policy.allow(k, r)[0])
    total = len(routes) * len(klasses)
    print(f"pre-probe policy: {skipped}/{total} (route,class) pairs excluded before any request "
          f"(RoE-aligned; {len(probe_policy.EXCLUSIONS)} exclusion rules)")
