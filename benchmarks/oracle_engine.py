"""Send a language-neutral exploit request to a running app and judge the outcome.

An exploit request (the engine contract shape) is a plain dict:

    {
      "method": "POST",
      "path": "/contributions",
      "headers": {...},                 # optional
      "body": {...} or "raw string",    # optional; dict → form-encoded
      "login_as": "user|admin|none",    # optional, default none
      "follow_redirects": false,        # optional, default false
      "success_if": {                   # the oracle: any key present must match
        "status": 302,
        "body_regex": "...",
        "redirect_regex": "...",
        "oob_marker": "ng-ssrf-abc"
      }
    }

`replay` on a tree returns exploitable=True when the response matches success_if.
Everything is stdlib so the harness adds no dependency, and every request is
throttled so probing can never flood the target (a Rules-of-Engagement limit).
"""
from __future__ import annotations

import http.cookiejar
import json
import http.server
import re
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

# (No application credentials live in the oracle engine. Each app supplies its own auth spec via `auth=` /
# --auth; each benchmark loads its own spec in its own driver.)
import os as _os
# Global request rate cap (RoE "throttled fuzzing"): min seconds between requests across ALL threads.
# Tunable via KAVACH_MIN_INTERVAL (e.g. 0.02 => 50 req/s). Serialized under a lock so the cap holds no
# matter how many concurrent workers run — this is the token-bucket the worker pool is bounded by.
_MIN_INTERVAL = float(_os.environ.get("KAVACH_MIN_INTERVAL", "0.05"))
_last_request = 0.0
_throttle_lock = threading.Lock()


def _throttle() -> None:
    global _last_request
    with _throttle_lock:                               # holding the lock during the sleep paces ALL threads
        wait = _MIN_INTERVAL - (time.monotonic() - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()


@dataclass
class Response:
    status: int
    body: str
    location: str      # the Location header, for redirect oracles
    set_cookie: str = ""  # the Set-Cookie header, for cookie-flag oracles
    content_type: str = ""  # the Content-Type header, so an XSS oracle can require an HTML context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401 - disable auto-follow
        return None


class Session:
    """A client against one base URL, redirects off by default.

    Auth is pluggable so the SAME oracles work across apps/languages.
    Pass an `auth` spec (login path + field names + roles->creds) per app; NO creds are built in. e.g. VAmPI JWT:
        {"kind": "bearer_json", "login_path": "/users/v1/login",
         "user_field": "username", "pass_field": "password", "token_field": "auth_token",
         "roles": {"admin": ["admin", "pass1"], "user": ["name1", "pass1"]}}
    What is app-specific (how to log in, how the token attaches) lives here; the oracle logic
    above (differential, idor, access-control, …) is unchanged across languages.
    """

    def __init__(self, base_url: str, follow_redirects: bool = False, auth: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.bearer: str | None = None
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if not follow_redirects:
            handlers.append(_NoRedirect())
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, method: str, path: str, *, headers=None, body=None) -> Response:
        _throttle()
        url = path if path.startswith("http") else self.base_url + path
        data = None
        hdrs = dict(headers or {})
        if self.bearer:
            hdrs.setdefault("Authorization", f"Bearer {self.bearer}")
        if body is not None:
            if isinstance(body, dict):
                if (self.auth or {}).get("body_json"):   # JSON APIs (VAmPI); default stays form-encoded
                    data = json.dumps(body).encode()
                    hdrs.setdefault("Content-Type", "application/json")
                else:
                    data = urllib.parse.urlencode(body).encode()
                    hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                data = str(body).encode()
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
        try:
            with self.opener.open(req, timeout=15) as resp:
                return Response(resp.status, resp.read().decode("utf-8", "replace"),
                                resp.headers.get("Location", ""), resp.headers.get("Set-Cookie", ""),
                                resp.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as e:
            return Response(e.code, e.read().decode("utf-8", "replace"),
                            e.headers.get("Location", ""), e.headers.get("Set-Cookie", ""),
                            e.headers.get("Content-Type", ""))

    def login(self, role: str) -> bool:
        if role in ("none", "", None):
            return True
        if self.auth:
            return self._login_via_spec(role)
        # No auth spec configured: the engine does NOT hardcode any app's credentials/login shape. An
        # authenticated class therefore cannot be confirmed without an --auth spec (login simply fails here).
        return False

    def _login_via_spec(self, role: str) -> bool:
        a = self.auth
        roles = a.get("roles", {})
        if role not in roles:
            raise ValueError(f"unknown login role {role!r} for this app")
        user, pw = roles[role]
        body = {a.get("user_field", "username"): user, a.get("pass_field", "password"): pw}
        # a login that posts JSON needs the JSON content-type even if body_json is off elsewhere
        prev, self.auth = self.auth, {**a, "body_json": a.get("kind") == "bearer_json" or a.get("body_json")}
        r = self.request("POST", a["login_path"], body=body)
        self.auth = prev
        if r.status not in (200, 201, 302):
            return False
        if a.get("kind") == "bearer_json":
            try:
                self.bearer = json.loads(r.body).get(a.get("token_field", "auth_token"))
            except (ValueError, AttributeError):
                return False
            return bool(self.bearer)
        return True


class _OOBServer:
    """A loopback-only HTTP server that serves a unique marker and records callbacks.

    For SSRF: the target is told to fetch this server. `{OOB_URL}` in the exploit is
    replaced by its address and `{OOB_MARKER}` by the token. An endpoint that reflects
    the fetched body proves the server made the request. The recorded hits also drive the `oob_marker` oracle for
    targets that do not reflect.
    """

    def __init__(self):
        self.token = "KAVACH-OOB-" + "".join(f"{b:02x}" for b in _rand(6))
        self.hits: set[str] = set()
        token, hits = self.token, self.hits

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.add(token)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(token.encode())

            def log_message(self, *a):  # silence
                pass

        self._srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self._srv.server_port}/{self.token}"

    def __enter__(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()


def _rand(n: int) -> bytes:
    import os
    return os.urandom(n)


def _spellings(url: str) -> dict:
    """The same loopback listener under other host spellings, for patches that block one literal host."""
    return {"{OOB_URL_LOCALHOST}": url.replace("127.0.0.1", "localhost", 1),
            "{OOB_URL_DECIMAL}": url.replace("127.0.0.1", "2130706433", 1)}


def _subst(obj, url: str, marker: str):
    if isinstance(obj, str):
        for placeholder, value in _spellings(url).items():
            obj = obj.replace(placeholder, value)
        return obj.replace("{OOB_URL}", url).replace("{OOB_MARKER}", marker)
    if isinstance(obj, dict):
        return {k: _subst(v, url, marker) for k, v in obj.items()}
    return obj


def run_exploit(base_url: str, exploit: dict, oob_hits: set[str] | None = None) -> tuple[bool, str]:
    """Return (exploitable, detail). exploitable=True ⇒ the oracle matched."""
    if exploit.get("differential"):
        return _differential(base_url, exploit)
    if exploit.get("idor"):
        return _idor(base_url, exploit)
    if exploit.get("write_idor"):
        return _write_idor(base_url, exploit)
    if exploit.get("access_control"):
        return _access_control(base_url, exploit)
    if exploit.get("oob"):
        with _OOBServer() as oob:
            ex = _subst(exploit, oob.url, oob.token)
            return _send(base_url, ex, oob.hits)
    return _send(base_url, exploit, oob_hits or set())


def _norm(body: str) -> str:
    """Collapse whitespace and strip digits so volatile values (random seed data,
    timestamps, ids) do not count as a difference — only structure remains."""
    return re.sub(r"\s+", " ", re.sub(r"\d+", "", body)).strip()


def _idor(base_url: str, exploit: dict) -> tuple[bool, str]:
    """Insecure-direct-object-reference oracle. As ONE user, request a resource whose id
    belongs to ANOTHER user (`foreign_request`) and the same resource for the user's own id
    (`own_request`). If the foreign request succeeds and returns DIFFERENT data, the app
    served another user's object from a URL id — confirmed, no app-specific marker (digits
    are the signal here, so bodies are compared raw, unlike the injection oracle). A fix that
    takes the id from the session returns the user's own data for both → identical → safe.
    """
    d = exploit["idor"]
    sess = Session(base_url, follow_redirects=bool(exploit.get("follow_redirects")), auth=exploit.get("auth"))
    if not sess.login(exploit.get("login_as", "user")):
        return False, "login failed"

    def hit(req):
        return sess.request(req.get("method", "GET"), req["path"],
                            headers=req.get("headers"), body=req.get("body"))

    foreign, own = hit(d["foreign_request"]), hit(d["own_request"])
    if foreign.status not in (200, 302):
        return False, f"foreign request not served (status {foreign.status})"
    if foreign.body == own.body:
        return False, "foreign and own ids return identical data (id is not taken from the URL)"
    return True, f"foreign id returned different data (status {foreign.status}, len {len(foreign.body)}/{len(own.body)})"


def _write_idor(base_url: str, exploit: dict) -> tuple[bool, str]:
    """Write-side IDOR / missing authorization, confirmed by VERIFY-AFTER-WRITE (a metamorphic relation
    the read-diff oracle cannot see when a mutation returns the same redirect for every id). As the
    attacker, write a distinctive marker into ANOTHER user's record; then read the resource back. If the
    marker is now visible, the attacker's write modified data they do not own. A fix that checks ownership
    or role denies the write, so the marker never appears. Baseline-reads first so a pre-existing marker
    cannot cause a false positive."""
    d = exploit["write_idor"]
    marker = d["marker"]

    def sess(role):
        s = Session(base_url, follow_redirects=bool(exploit.get("follow_redirects")), auth=exploit.get("auth"))
        return s if s.login(role) else None

    reader, writer = sess(d.get("read_as", "user")), sess(d.get("write_as", "user"))
    if reader is None or writer is None:
        return False, "login failed"
    rr, wr = d["read_request"], d["write_request"]

    def read():
        return reader.request(rr.get("method", "GET"), rr["path"], headers=rr.get("headers"), body=rr.get("body"))

    if marker in read().body:
        return False, f"marker {marker!r} already present before the write (inconclusive)"
    writer.request(wr.get("method", "POST"), wr["path"], headers=wr.get("headers"), body=wr.get("body"))
    if marker in read().body:
        return True, f"attacker's write landed in another user's record (marker {marker!r} now readable)"
    return False, "the write did not change the readable resource (ownership/role enforced)"


def _denied(r: Response) -> bool:
    """A request an app refused: an auth error, or a redirect to a login/landing page."""
    if r.status in (401, 403):
        return True
    if r.status in (301, 302, 303, 307, 308):
        loc = r.location.lower()
        return "login" in loc or loc.rstrip("/") in ("", "/dashboard", "/home")
    return r.status >= 400


def _access_control(base_url: str, exploit: dict) -> tuple[bool, str]:
    """Broken-access-control oracle (a metamorphic relation): perform the SAME privileged
    request as an AUTHORIZED role and as an UNAUTHORIZED one. The property is that the
    unauthorized request must be denied — so if it is served just like the authorized one,
    access control is broken. Generic: no app marker, just "who is allowed vs who is served".
    A fix that adds a role check makes the unauthorized request redirect/403 → safe.

    `setup` (optional): requests run FIRST as `setup_as`, to create the object the comparison needs
    (e.g. store a book as its owner before another user reads it). This keeps the exploit self-contained
    so the repair gate can replay it against a freshly-seeded app.
    """
    d = exploit["access_control"]
    req = d["request"]

    if d.get("setup"):
        s = Session(base_url, follow_redirects=False, auth=d.get("auth") or exploit.get("auth"))
        if not s.login(d.get("setup_as", d.get("authorized", "admin"))):
            return False, "setup login failed"
        for step in d["setup"]:
            s.request(step.get("method", "GET"), step["path"],
                      headers=step.get("headers"), body=step.get("body"))

    def run(role):
        s = Session(base_url, follow_redirects=False, auth=d.get("auth") or exploit.get("auth"))
        if not s.login(role):
            return None
        return s.request(req.get("method", "GET"), req["path"],
                        headers=req.get("headers"), body=req.get("body"))

    auth = run(d.get("authorized", "admin"))
    unauth = run(d.get("unauthorized", "user"))
    if auth is None or unauth is None:
        return False, "login failed"
    if _denied(auth):
        return False, f"the authorized role is itself denied (status {auth.status}); not a working privileged action"
    if _denied(unauth):
        return False, f"the unauthorized role is denied (status {unauth.status}) — access control holds"
    return True, f"unauthorized role served the privileged action (status {unauth.status}, same as authorized)"


def _differential(base_url: str, exploit: dict) -> tuple[bool, str]:
    """Boolean-based injection oracle: send a condition that is always TRUE and one that
    is always FALSE. If the app's responses differ in structure, request data reached the
    query logic — confirmed without any app-specific marker (the 'benign baseline' that a
    reflection oracle cannot give for SQL/NoSQL). A patch that parses/escapes the input
    makes both requests behave identically, so the difference vanishes.
    """
    d = exploit["differential"]
    login = exploit.get("login_as", "none")
    sess = Session(base_url, follow_redirects=bool(exploit.get("follow_redirects")), auth=exploit.get("auth"))
    if not sess.login(login):
        return False, "login failed"

    def hit(req):
        return sess.request(req.get("method", "GET"), req["path"],
                            headers=req.get("headers"), body=req.get("body"))

    t, f = hit(d["true_request"]), hit(d["false_request"])
    if _norm(t.body) != _norm(f.body) or t.status != f.status:
        return True, f"true≠false (status {t.status}/{f.status}, len {len(t.body)}/{len(f.body)})"
    return False, "true and false conditions give the same response (input does not reach the query)"


def _send(base_url: str, exploit: dict, oob_hits: set[str]) -> tuple[bool, str]:
    sess = Session(base_url, follow_redirects=bool(exploit.get("follow_redirects")), auth=exploit.get("auth"))
    if not sess.login(exploit.get("login_as", "none")):
        return False, "login failed"
    # Optional setup requests run in the same session first (e.g. store a stored-XSS
    # payload, then read it back with the oracle request below).
    for step in exploit.get("setup", []):
        sess.request(step.get("method", "GET"), step["path"],
                     headers=step.get("headers"), body=step.get("body"))
    resp = sess.request(exploit.get("method", "GET"), exploit["path"],
                        headers=exploit.get("headers"), body=exploit.get("body"))
    return _matches(resp, exploit.get("success_if", {}), oob_hits)


def _matches(resp: Response, oracle: dict, oob_hits: set[str]) -> tuple[bool, str]:
    if not oracle:
        return False, "no success_if oracle given"
    reasons = []
    if oracle.get("require_html") and "html" not in resp.content_type.lower():
        # a payload reflected into a JSON/text response is not XSS — it only executes in an HTML context
        return False, f"not an HTML response (Content-Type: {resp.content_type or 'unknown'})"
    if "status" in oracle:
        if resp.status != oracle["status"]:
            return False, f"status {resp.status} != {oracle['status']}"
        reasons.append(f"status={resp.status}")
    if "body_regex" in oracle:
        if not re.search(oracle["body_regex"], resp.body, re.S):
            return False, f"body_regex /{oracle['body_regex']}/ not found"
        reasons.append("body matched")
    if "redirect_regex" in oracle:
        if not re.search(oracle["redirect_regex"], resp.location):
            return False, f"redirect /{oracle['redirect_regex']}/ not in Location={resp.location!r}"
        reasons.append(f"redirect={resp.location}")
    if "set_cookie_regex" in oracle:
        if not re.search(oracle["set_cookie_regex"], resp.set_cookie):
            return False, f"set_cookie /{oracle['set_cookie_regex']}/ not in {resp.set_cookie!r}"
        reasons.append("set-cookie matched")
    if "oob_marker" in oracle:
        if oracle["oob_marker"] not in oob_hits:
            return False, f"oob marker {oracle['oob_marker']!r} never called back"
        reasons.append("oob callback received")
    return True, "; ".join(reasons)
