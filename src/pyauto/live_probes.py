"""Language-agnostic live PROVE stage: deterministic HTTP oracles against a running instance.

These checks know nothing about the app's language or framework — they drive a route list over HTTP and
judge by fixed, self-validating rules, so they work the same on a Java, Python or Node target. They cover
the classes our source/injection oracles cannot reach (headers, cookies, CORS, host-header, rate limit,
username enumeration, session-token predictability, JWT forging, CSRF, sensitive data) and three marker
oracles (open redirect, reflected XSS, response-header injection).

Every finding here is either a FACT (a header is absent/misconfigured — cannot be a false positive) or a
REPLAYED EXPLOIT (a guessed JWT secret verifies a token; a payload reflects unencoded). So the whole set is
safe to put in the CONFIRMED tier: nothing unproven is ever reported. Promoted from the experimental
version (exp/scripts/live_checks.py) into the engine; loopback-only, sequential, capped.

Input routes are the generic route-map shape {method, path, params, param_annotations, file, function,
body} produced for ANY framework by the route extractor (or our own discovery). Output is confirmed
Findings in the shared model.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import json
import math
import re
import uuid
from urllib.parse import urlparse

import requests

from src.jsauto.findings import Finding, apply_security

COMMON = ["id", "name", "url", "file", "fileName", "q", "search", "value", "input", "username", "user",
          "password", "email", "content", "comment", "data", "returnTo", "redirect", "next", "target",
          "path", "page", "key", "token", "level", "message", "text", "host", "address", "payload", "cmd"]
REDIR = {"returnto", "redirect", "next", "url", "target", "dest", "destination", "continue", "return",
         "redirect_uri", "return_to", "goto", "link"}
MAPLIKE = {"queryparams", "request", "input", "requestbody", "params", "body", "data", "model", "map", "payload"}
SKIPNAMES = {"response", "session", "file", "files", "multipartfile", "httpservletrequest", "httpservletresponse"}
JWT_RE = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*")
WORDS = ["secret", "password", "123456", "changeme", "key", "jwt", "admin", "random", "test", "default",
         "supersecret", "s3cret", "secretkey", "jwtsecret", "mysecret", "your-256-bit-secret", "qwerty",
         "letmein", "token", "topsecret", "password123", "admin123", "hmackey", "signingkey", "private"]
LOCK_RE = re.compile(r"(?i)(locked|too many|rate.?limit|try again later|captcha|throttl|blocked)")
SENS_RE = re.compile(r'(?i)"(password|passwd|pwd|secret|api_?key|token|ssn|credit_?card|private_?key)"\s*:\s*"[^"]+"')


class Live:
    def __init__(self, base: str, ctx: str, budget: int):
        h = urlparse(base).hostname
        if h not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(f"live PROVE refuses non-loopback target {h!r} (RoE: own instance only)")
        self.base, self.ctx, self.budget, self.n = base.rstrip("/"), ctx.rstrip("/"), budget, 0
        self.findings: list[Finding] = []
        self.creds: list = []

    def req(self, method, url, **kw):
        if self.n >= self.budget:
            return None
        self.n += 1
        try:
            return requests.request(method, url, timeout=10, allow_redirects=False, **kw)
        except requests.RequestException:
            return None

    def add(self, route, klass, detail):
        f = Finding(id=f"live:{klass}:{route}", source="live", klass=klass, file="(runtime)",
                    rule="live-oracle", status="confirmed", confidence="high",
                    message=detail, reason=detail, evidence={"route": route, "detail": detail})
        self.findings.append(apply_security(f, "EXTERNAL", detail))


def _url(L, r):
    p = r["path"] if r["path"].startswith("/") else "/" + r["path"]
    p = re.sub(r"\{[^}]*\}", "1", p)
    return L.base + (L.ctx if not p.startswith(L.ctx) else "") + p


def _param_plan(r):
    names = [p for p in r.get("params", []) if p.lower() not in SKIPNAMES]
    expand = (not names) or any(p.lower() in MAPLIKE for p in names)
    return list(dict.fromkeys([p for p in names if p.lower() not in MAPLIKE] + (COMMON if expand else [])))


def _mk(k):
    return "kv" + re.sub(r"\W", "", k)[:5] + uuid.uuid4().hex[:5]


def _methods(r):
    return [r["method"]] if r["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH") else ["GET", "POST"]


def _baseline(L, r, keys):
    markers = {k: _mk(k) for k in keys}
    u = _url(L, r)
    last = None
    for m in _methods(r):
        kw = {"params": markers}
        if m != "GET":
            kw = {"params": markers, "data": markers}
        if r.get("body") or "RequestBody" in (r.get("param_annotations") or []):
            body = dict(markers)
            body.update({"username": "admin", "password": "admin", "email": "admin@example.com", "action": "login"})
            kw = {"json": body}
        resp = L.req(m, u, **kw)
        last = (m, resp, markers)
        if resp is not None and resp.status_code not in (404, 405):
            return m, resp, markers
    return last


def _headers(L, rid, resp):
    h = {k.lower(): v for k, v in resp.headers.items()}
    xfo, csp = h.get("x-frame-options", ""), h.get("content-security-policy", "")
    fa = re.search(r"frame-ancestors\s+([^;]+)", csp or "", re.I)
    weak = (not xfo and not fa) or re.search(r"(?i)allow-?all|allow-from", xfo or "") or (fa and "*" in fa.group(1).split())
    if weak:
        L.add(rid, "clickjacking", f"X-Frame-Options={xfo or 'absent'}; CSP frame-ancestors={fa.group(1) if fa else 'absent'}")
    raw = getattr(resp, "raw", None)
    cookies = raw.headers.getlist("Set-Cookie") if raw is not None and hasattr(raw.headers, "getlist") else []
    for sc in cookies:
        name, low = sc.split("=", 1)[0].strip(), sc.lower()
        if "httponly" not in low:
            L.add(rid, "cookie-flags", f"cookie {name} lacks HttpOnly")
        if "samesite" not in low:
            L.add(rid, "cookie-samesite", f"cookie {name} lacks SameSite")


def _cors(L, rid, u, m):
    r = L.req(m, u, headers={"Origin": "https://kvevil.example"})
    if r is None:
        return
    ao = r.headers.get("Access-Control-Allow-Origin", "")
    cred = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if ao == "https://kvevil.example" or (ao == "*" and cred):
        L.add(rid, "cors-misconfig", f"ACAO={ao} credentials={cred}")


def _host(L, rid, u, m, markers):
    r = L.req(m, u, params=markers, headers={"X-Forwarded-Host": "kvevil.example", "X-Host": "kvevil.example",
                                             "X-Forwarded-Server": "kvevil.example"})
    if r is not None and "kvevil.example" in (r.text + json.dumps(dict(r.headers))):
        L.add(rid, "host-header-reflection", "X-Forwarded-Host value reflected in response")


def _reflection(L, rid, u, m, markers, resp):
    refl = [k for k, v in markers.items() if v in (resp.text or "")]
    hdr = [k for k, v in markers.items() if v in json.dumps(dict(resp.headers))]
    for k in refl[:4]:
        probe = f'"><kv{uuid.uuid4().hex[:5]}>'
        r = L.req(m, u, params={k: probe}, **({"data": {k: probe}} if m != "GET" else {}))
        # require an HTML content-type: a payload echoed in a JSON/text response is not executed by a
        # browser, so it is not XSS — guarding here keeps the confirmed tier false-positive-free.
        if r is not None and probe in (r.text or "") and "html" in r.headers.get("Content-Type", "").lower():
            L.add(rid, "xss-reflected", f"param {k} reflected unencoded in HTML: {probe}")
            break
    for k in hdr[:3]:
        r = L.req(m, u, params={k: "a\r\nX-Kv-Injected: 1"})
        if r is not None and "x-kv-injected" in {x.lower() for x in r.headers}:
            L.add(rid, "header-injection", f"param {k} injected a response header")


def _redirect(L, rid, u, m, keys):
    for k in [k for k in keys if k.lower() in REDIR]:
        for payload in ("//kvevil.example/x", "https://kvevil.example/x"):
            r = L.req(m, u, params={k: payload})
            if r is not None and 300 <= r.status_code < 400 and "kvevil.example" in r.headers.get("Location", ""):
                L.add(rid, "open-redirect", f"param {k} -> Location {r.headers['Location']}")
                return


def _is_login(r, keys):
    blob = (r["path"] + " " + r.get("function", "")).lower()
    return bool(re.search(r"login|signin|authenticate|/auth|session", blob)) or \
        any(re.search(r"pass(word)?|pwd|loginrequest", k, re.I) for k in r.get("params", []))


def _norm(resp):
    return (resp.status_code, re.sub(r"\d+", "#", resp.text or "")[:300])


def _login_checks(L, rid, r, u, m):
    def attempt(user, passwd="Wr0ng-kv-pass!"):
        body = {"username": user, "password": passwd, "email": user, "user": user, "name": user,
                "login": user, "userName": user}
        kw = ({"json": body} if (r.get("body") or "RequestBody" in (r.get("param_annotations") or []))
              else ({"params": body} if m == "GET" else {"data": body, "params": body}))
        return L.req(m, u, **kw)

    if L.creds:
        ok = attempt(L.creds[0], L.creds[1])
        if ok is not None and ok.status_code < 400:
            _jwt(L, rid, ok)
    base = [attempt("kv" + uuid.uuid4().hex[:8]) for _ in range(2)]
    if None in base:
        return
    if len({_norm(b) for b in base}) != 1:
        base = base[:1]
    for cand in ("admin", "user", "test", "john", "root", "administrator", "alice", "bob"):
        a = [attempt(cand), attempt(cand)]
        if None in a or len({_norm(x) for x in a}) != 1:
            continue
        if _norm(a[0]) != _norm(base[0]) and a[0].status_code < 500:
            L.add(rid, "user-enumeration",
                  f"'{cand}' answers {a[0].status_code} vs unknown user {base[0].status_code}")
            break
    codes, locked = [], False
    for i in range(20):
        x = attempt("admin", f"Wr0ng-kv-{i}")
        if x is None:
            break
        codes.append(x.status_code)
        if x.status_code in (423, 429) or x.headers.get("Retry-After") or LOCK_RE.search(x.text or ""):
            locked = True
            break
    if codes and not locked and len(codes) >= 20:
        L.add(rid, "no-rate-limit", f"{len(codes)} wrong-password attempts, statuses {sorted(set(codes))}, no lockout")


def _entropy_bits(vals):
    cs = len(set("".join(vals)))
    return min(len(v) for v in vals) * math.log2(max(cs, 2))


def _session(L, rid, u, m, markers):
    vals = collections.defaultdict(list)
    for _ in range(8):
        r = L.req(m, u, params=markers)
        if r is None:
            return
        raw = getattr(r, "raw", None)
        for sc in (raw.headers.getlist("Set-Cookie") if raw is not None and hasattr(raw.headers, "getlist") else []):
            n, _, v = sc.split(";")[0].partition("=")
            if re.search(r"(?i)(sess|sid|token|auth|jwt)", n):
                vals[n.strip()].append(v.strip())
    for n, vs in vals.items():
        if len(vs) < 6:
            continue
        weak = []
        if len(set(vs)) < len(vs):
            weak.append("repeats")
        if all(re.fullmatch(r"\d+", v) for v in vs):
            nums = [int(v) for v in vs]
            d = {b - a for a, b in zip(nums, nums[1:])}
            weak.append("numeric" + (" sequential" if len(d) <= 2 else ""))
        if _entropy_bits(vs) < 48:
            weak.append(f"~{int(_entropy_bits(vs))} bits")
        if weak:
            L.add(rid, "predictable-session-id", f"cookie {n}: {', '.join(weak)}")


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwt(L, rid, resp):
    toks = set(JWT_RE.findall(resp.text or "")) | set(JWT_RE.findall(json.dumps(dict(resp.headers))))
    for t in list(toks)[:2]:
        try:
            head = json.loads(_b64d(t.split(".")[0]))
            pay = json.loads(_b64d(t.split(".")[1]))
        except Exception:  # noqa: BLE001 — a malformed token is not a finding
            continue
        alg = str(head.get("alg", ""))
        if alg.lower() == "none":
            L.add(rid, "jwt-none-alg", "issued token uses alg=none")
        if alg.upper().startswith("HS"):
            hm = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg.upper())
            h, p, sig = t.split(".")
            for w in WORDS:
                if hm and hmac.new(w.encode(), f"{h}.{p}".encode(), hm).digest() == _b64d(sig):
                    L.add(rid, "jwt-weak-secret", f"{alg} signature verifies with guessable secret '{w}'")
                    break
        if "exp" not in pay:
            L.add(rid, "jwt-no-expiry", "token has no exp claim")


def _form(L, rid, resp):
    if "html" not in resp.headers.get("Content-Type", "").lower():
        return
    for frm in re.findall(r"(?is)<form\b[^>]*>.*?</form>", resp.text or ""):
        if not re.search(r"(?i)method\s*=\s*[\"']?post", frm):
            continue
        toks = re.findall(r"(?is)<input\b[^>]*name\s*=\s*[\"'](?:_?csrf\w*|_?xsrf\w*|authenticity_token|_token|nonce|anti-?forgery\w*)[\"'][^>]*>", frm)
        if not toks:
            L.add(rid, "csrf-missing", "HTML POST form without an anti-CSRF token field")
            return
        if all(not re.search(r"(?is)value\s*=\s*[\"'][^\"']+[\"']", t) for t in toks):
            L.add(rid, "csrf-missing", "anti-CSRF token field present but rendered empty")
            return


def _sensitive(L, rid, r, resp):
    if _is_login(r, []):
        return
    mm = SENS_RE.search(resp.text or "")
    if mm:
        L.add(rid, "sensitive-data-exposure", f"response contains {mm.group(0)[:40]}")


# privileged fields a client should NOT be able to set (mined from strix mass_assignment.md)
_PRIV_FIELDS = ["isAdmin", "is_admin", "admin", "role", "roles", "is_active", "active", "verified",
                "emailVerified", "premium", "isSuperuser", "is_staff", "is_superuser", "account_type"]


def _cache_poison(L, rid, u, m):
    """Web cache poisoning by the 3-request method (0-FP): on a cache-buster URL (so we only ever touch a
    synthetic key, never a real cached path), send an unkeyed header carrying a UNIQUE marker; then request
    the SAME url as a victim with NO malicious header. If the victim response carries the marker, the cache
    served attacker-controlled unkeyed input — confirmed. Unique marker => no coincidence. Safe on an
    isolated instance; bounded (one synthetic key)."""
    if m != "GET":
        return
    marker = "kvcp" + uuid.uuid4().hex[:8]
    url = u + ("&" if "?" in u else "?") + "kvcb=" + uuid.uuid4().hex[:8]     # synthetic cache key
    atk = L.req("GET", url, headers={"X-Forwarded-Host": f"{marker}.evil", "X-Host": f"{marker}.evil",
                                     "X-Forwarded-Scheme": "nothttps"})
    if atk is None:
        return
    victim = L.req("GET", url)                                               # no malicious header
    if victim is not None and marker in (victim.text + json.dumps(dict(victim.headers))):
        L.add(rid, "web-cache-poisoning",
              f"unkeyed header reflected to a victim via the cache (marker {marker!r} on a cache-buster key)")


def _mass_assign(L, rid, r, u, m):
    """Mass-assignment by VERIFY-AFTER-WRITE (0-FP): on a write route, send an extra privileged field set to
    a UNIQUE marker, then read the resource back; if the marker appears, the server accepted a field the
    client should not control. The marker is unique so a hit cannot be coincidence. Non-destructive (sets a
    field on our own instance). Best-effort: only fires when a same-path GET reads the object back."""
    if m not in ("POST", "PUT", "PATCH"):
        return
    marker = "kvma" + uuid.uuid4().hex[:8]
    before = L.req("GET", u)
    if before is None or marker in (before.text or ""):
        return
    body = {f: (marker if f in ("role", "roles", "account_type") else True) for f in _PRIV_FIELDS}
    body.update({"username": "kvuser", "name": "kvuser", "email": "kv@example.com"})   # plausible payload
    kw = {"json": body} if (r.get("body") or "RequestBody" in (r.get("param_annotations") or [])) else {"data": body}
    if L.req(m, u, **kw) is None:
        return
    after = L.req("GET", u)
    if after is not None and marker in (after.text or ""):
        L.add(rid, "mass-assignment", f"privileged field accepted: unique marker {marker!r} persisted after writing it")


# Classes that are an app-WIDE config fact (a header/policy missing everywhere), not a per-route bug. Reported
# ONCE, not once per route — 40 identical "missing X-Frame-Options" findings read as false-positive spam and
# the real issue is a single site-wide one. Per-route exploit classes (reflected XSS, open redirect, host-
# header, header injection, enumeration, sensitive data, predictable session) stay per route.
_GLOBAL = {"clickjacking", "cookie-flags", "cookie-samesite", "cors-misconfig", "csrf-missing",
           "no-rate-limit", "jwt-none-alg", "jwt-weak-secret", "jwt-no-expiry"}


def _collapse(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per app-global class; keep all per-route findings. The kept global finding notes how
    many routes exhibited it, so the breadth is not lost."""
    seen_global, out = {}, []
    counts = collections.Counter(f.klass for f in findings if f.klass in _GLOBAL)
    for f in findings:
        if f.klass in _GLOBAL:
            if f.klass in seen_global:
                continue
            seen_global[f.klass] = True
            n = counts[f.klass]
            if n > 1:
                f.reason = f.message = f"{f.message} (site-wide: {n} routes affected)"
                f.evidence["affected_routes"] = n
        out.append(f)
    return out


def live_confirm(base_url: str, routes: list[dict], ctx: str = "", budget: int = 900, creds=None) -> list[Finding]:
    """Run every language-agnostic HTTP oracle over the route list; return CONFIRMED Findings. `routes` is
    the generic route-map shape; `ctx` is a base path prefix (e.g. /VulnerableApp); `creds` an optional
    [user, pass] to exercise authenticated JWT issuance. Loopback-only, capped at `budget` requests."""
    L = Live(base_url, ctx, budget)
    L.creds = creds or []
    for r in routes:
        rid = f'{r["method"]} {r["path"]}'
        if r.get("file") == "" and str(r.get("function", "")).startswith("<"):
            continue
        if r.get("params") and any(p.lower() in {"file", "multipartfile"} for p in r["params"]) and r["method"] == "POST":
            continue                                      # multipart upload: not driven here
        keys = _param_plan(r)
        got = _baseline(L, r, keys)
        if not got or got[1] is None or got[1].status_code in (404, 405):
            continue
        m, resp, markers = got
        u = _url(L, r)
        _headers(L, rid, resp)
        _cors(L, rid, u, m)
        _host(L, rid, u, m, markers)
        _reflection(L, rid, u, m, markers, resp)
        _redirect(L, rid, u, m, keys)
        _jwt(L, rid, resp)
        _form(L, rid, resp)
        _sensitive(L, rid, r, resp)
        _mass_assign(L, rid, r, u, m)
        _cache_poison(L, rid, u, m)
        if re.search(r"(?i)set-cookie", json.dumps(dict(resp.headers))) or resp.cookies:
            _session(L, rid, u, m, markers)
        if _is_login(r, keys):
            _login_checks(L, rid, r, u, m)
    return _collapse(L.findings)
