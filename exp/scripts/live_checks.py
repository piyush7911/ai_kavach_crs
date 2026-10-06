"""Step 5: live deterministic checks against a running instance, driven by the route map. No LLM.

    python -m exp.scripts.live_checks <base_url> <routes.json> <out.json> [--ctx /VulnerableApp] [--seed /createdb] [--budget 900]

Loopback only (refuses any other host). Every check is a fixed oracle with a stated rule; requests are sequential and capped.
Checks: framing protection (X-Frame-Options / CSP frame-ancestors), cookie flags, CORS, host-header reflection, login rate limiting,
username enumeration (differential), session-token predictability (entropy / sequence), JWT (alg none, weak HS256 secret by short wordlist),
CSRF token in HTML forms, sensitive fields in responses, and three marker oracles: open redirect, reflected XSS, response-header injection.
Output: findings [{route, class, evidence}] and per-route baselines.
"""
import argparse, base64, collections, hashlib, hmac, json, math, re, sys, time, uuid
from urllib.parse import urlparse
import requests

COMMON = ["id", "name", "url", "file", "fileName", "q", "search", "value", "input", "username", "user", "password", "email", "content", "comment", "data",
          "returnTo", "redirect", "next", "target", "path", "page", "key", "token", "level", "message", "text", "host", "address", "payload", "cmd"]
REDIR = {"returnto", "redirect", "next", "url", "target", "dest", "destination", "continue", "return", "redirect_uri", "return_to", "goto", "link"}
MAPLIKE = {"queryparams", "request", "input", "requestbody", "params", "body", "data", "model", "map", "payload"}
SKIPNAMES = {"response", "session", "file", "files", "multipartfile", "httpservletrequest", "httpservletresponse"}
JWT_RE = re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]*")
WORDS = ["secret", "password", "123456", "changeme", "key", "jwt", "admin", "random", "test", "default", "supersecret", "s3cret", "secretkey", "jwtsecret", "mysecret",
         "your-256-bit-secret", "qwerty", "letmein", "token", "topsecret", "password123", "admin123", "hmackey", "signingkey", "private"]
LOCK_RE = re.compile(r"(?i)(locked|too many|rate.?limit|try again later|captcha|throttl|blocked)")
SENS_RE = re.compile(r'(?i)"(password|passwd|pwd|secret|api_?key|token|ssn|credit_?card|private_?key)"\s*:\s*"[^"]+"')
S = requests.Session(); S.trust_env = False

class Live:
    def __init__(self, base, ctx, budget):
        h = urlparse(base).hostname
        if h not in ("127.0.0.1", "localhost", "::1"): raise SystemExit("refusing non-loopback target " + str(h))
        self.base, self.ctx, self.budget, self.n = base.rstrip("/"), ctx.rstrip("/"), budget, 0
        self.findings, self.baselines, self.creds = [], {}, []

    def req(self, method, url, **kw):
        if self.n >= self.budget: return None
        self.n += 1
        try: return requests.request(method, url, timeout=10, allow_redirects=False, **kw)
        except requests.RequestException: return None

    def add(self, route, cls, evidence): self.findings.append({"route": route, "class": cls, "evidence": evidence})

def url_of(L, r):
    p = r["path"] if r["path"].startswith("/") else "/" + r["path"]
    p = re.sub(r"\{[^}]*\}", "1", p)
    return L.base + (L.ctx if not p.startswith(L.ctx) else "") + p

def param_plan(r):
    """(query dict with unique markers, marker->name). Unknown/map-like parameters expand to common names."""
    names = [p for p in r.get("params", []) if p.lower() not in SKIPNAMES]
    expand = (not names) or any(p.lower() in MAPLIKE for p in names) or "RequestParam" in (r.get("param_annotations") or []) and any(p.lower() in MAPLIKE for p in names)
    keys = list(dict.fromkeys([p for p in names if p.lower() not in MAPLIKE] + (COMMON if expand else [])))
    return keys

def mk(k): return "kv" + re.sub(r"\W", "", k)[:5] + uuid.uuid4().hex[:5]

def methods_for(r): return [r["method"]] if r["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH") else ["GET", "POST"]

def baseline(L, r, keys):
    markers = {k: mk(k) for k in keys}; u = url_of(L, r); last = None
    for m in methods_for(r):
        kw = {"params": markers} if m == "GET" or True else {}
        if m != "GET": kw = {"params": markers, "data": markers}
        if r.get("body") or "RequestBody" in (r.get("param_annotations") or []):
            body = {k: v for k, v in markers.items()}; body.update({"username": "admin", "password": "admin", "email": "admin@example.com", "action": "login"}); kw = {"json": body}
        resp = L.req(m, u, **kw); last = (m, resp, markers)
        if resp is not None and resp.status_code not in (404, 405): return m, resp, markers
    return last

def analyse_headers(L, rid, resp):
    h = {k.lower(): v for k, v in resp.headers.items()}
    xfo = h.get("x-frame-options", ""); csp = h.get("content-security-policy", "")
    fa = re.search(r"frame-ancestors\s+([^;]+)", csp or "", re.I)
    weak = (not xfo and not fa) or re.search(r"(?i)allow-?all|allow-from", xfo or "") or (fa and "*" in fa.group(1).split())
    if weak: L.add(rid, "clickjacking", f"X-Frame-Options={xfo or 'absent'}; CSP frame-ancestors={fa.group(1) if fa else 'absent'}")
    for sc in resp.raw.headers.getlist("Set-Cookie") if getattr(resp, "raw", None) is not None and hasattr(resp.raw.headers, "getlist") else []:
        name = sc.split("=", 1)[0].strip(); low = sc.lower()
        if "httponly" not in low: L.add(rid, "cookie-flags", f"cookie {name} lacks HttpOnly")
        if "samesite" not in low: L.add(rid, "cookie-samesite", f"cookie {name} lacks SameSite")

def check_cors(L, rid, u, m):
    r = L.req(m, u, headers={"Origin": "https://kvevil.example"})
    if r is None: return
    ao = r.headers.get("Access-Control-Allow-Origin", ""); cred = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if ao == "https://kvevil.example" or (ao == "*" and cred): L.add(rid, "cors-misconfig", f"ACAO={ao} credentials={cred}")

def check_host(L, rid, u, m, markers):
    r = L.req(m, u, params=markers, headers={"X-Forwarded-Host": "kvevil.example", "X-Host": "kvevil.example", "X-Forwarded-Server": "kvevil.example"})
    if r is None: return
    blob = r.text + json.dumps(dict(r.headers))
    if "kvevil.example" in blob: L.add(rid, "host-header-reflection", "X-Forwarded-Host value reflected in response")

def check_reflection(L, rid, u, m, markers, resp):
    refl = [k for k, v in markers.items() if v in (resp.text or "")]
    hdr = [k for k, v in markers.items() if v in json.dumps(dict(resp.headers))]
    for k in refl[:4]:
        probe = f'"><kv{uuid.uuid4().hex[:5]}>'
        r = L.req(m, u, params={k: probe}, **({"data": {k: probe}} if m != "GET" else {}))
        if r is not None and probe in r.text and "kv" in probe: L.add(rid, "xss-reflected", f"param {k} reflected unencoded: {probe}"); break
    for k in hdr[:3]:
        r = L.req(m, u, params={k: "a\r\nX-Kv-Injected: 1"})
        if r is not None and "x-kv-injected" in {x.lower() for x in r.headers}: L.add(rid, "header-injection", f"param {k} injected a response header")

def check_redirect(L, rid, u, m, keys):
    cands = [k for k in keys if k.lower() in REDIR]
    for k in cands:
        for payload in ("//kvevil.example/x", "https://kvevil.example/x"):
            r = L.req(m, u, params={k: payload})
            if r is not None and 300 <= r.status_code < 400 and "kvevil.example" in r.headers.get("Location", ""):
                L.add(rid, "open-redirect", f"param {k} -> Location {r.headers['Location']}"); return

def is_login(r, keys):
    blob = (r["path"] + " " + r["function"]).lower()
    return bool(re.search(r"login|signin|authenticate|/auth|session", blob)) or any(re.search(r"pass(word)?|pwd|loginrequest", k, re.I) for k in r.get("params", []))

def norm(resp): return (resp.status_code, re.sub(r"\d+", "#", resp.text or "")[:300])

def login_checks(L, rid, r, u, m):
    users, pw = "username", "password"
    def attempt(user, passwd="Wr0ng-kv-pass!"):
        body = {"username": user, "password": passwd, "email": user, "user": user, "name": user, "login": user, "userName": user}
        kw = {"json": body} if (r.get("body") or "RequestBody" in (r.get("param_annotations") or [])) else ({"params": body} if m == "GET" else {"data": body, "params": body})
        return L.req(m, u, **kw)
    if L.creds:
        ok = attempt(L.creds[0], L.creds[1])
        if ok is not None and ok.status_code < 400:
            jwt_checks(L, rid, ok)
    base = [attempt("kv" + uuid.uuid4().hex[:8]) for _ in range(2)]
    if None in base: return
    if len({norm(b) for b in base}) != 1: base = base[:1]
    for cand in ("admin", "user", "test", "john", "root", "administrator", "alice", "bob"):
        a = [attempt(cand), attempt(cand)]
        if None in a or len({norm(x) for x in a}) != 1: continue
        if norm(a[0]) != norm(base[0]) and a[0].status_code < 500:
            L.add(rid, "user-enumeration", f"'{cand}' answers {a[0].status_code} '{(a[0].text or '')[:60]}' vs unknown user {base[0].status_code} '{(base[0].text or '')[:60]}'"); break
    codes, locked = [], False
    for i in range(20):
        x = attempt("admin", f"Wr0ng-kv-{i}")
        if x is None: break
        codes.append(x.status_code)
        if x.status_code in (423, 429) or x.headers.get("Retry-After") or LOCK_RE.search(x.text or ""): locked = True; break
    if codes and not locked and len(codes) >= 20: L.add(rid, "no-rate-limit", f"{len(codes)} wrong-password attempts, statuses {sorted(set(codes))}, no lockout / 429 / Retry-After")

def entropy_bits(vals):
    cs = len(set("".join(vals))); L_ = min(len(v) for v in vals); return L_ * math.log2(max(cs, 2))

def session_checks(L, rid, u, m, markers):
    vals = collections.defaultdict(list)
    for _ in range(8):
        r = L.req(m, u, params=markers)
        if r is None: return
        for sc in (r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []):
            n, _, v = sc.split(";")[0].partition("=")
            if re.search(r"(?i)(sess|sid|token|auth|jwt)", n): vals[n.strip()].append(v.strip())
    for n, vs in vals.items():
        if len(vs) < 6: continue
        weak = []
        if len(set(vs)) < len(vs): weak.append("repeats")
        if all(re.fullmatch(r"\d+", v) for v in vs):
            nums = [int(v) for v in vs]; d = {b - a for a, b in zip(nums, nums[1:])}
            weak.append("numeric" + (" sequential" if len(d) <= 2 else ""))
        if entropy_bits(vs) < 48: weak.append(f"~{int(entropy_bits(vs))} bits")
        if weak: L.add(rid, "predictable-session-id", f"cookie {n}: {', '.join(weak)}; samples {vs[:3]}")

def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jwt_checks(L, rid, resp):
    toks = set(JWT_RE.findall(resp.text or "")) | set(JWT_RE.findall(json.dumps(dict(resp.headers))))
    for t in list(toks)[:2]:
        try: head = json.loads(b64d(t.split(".")[0])); pay = json.loads(b64d(t.split(".")[1]))
        except Exception: continue
        alg = str(head.get("alg", ""))
        if alg.lower() == "none": L.add(rid, "jwt-none-alg", "issued token uses alg=none")
        if alg.upper().startswith("HS"):
            hm = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg.upper())
            h, p, sig = t.split(".");
            for w in WORDS:
                if hm and hmac.new(w.encode(), f"{h}.{p}".encode(), hm).digest() == b64d(sig): L.add(rid, "jwt-weak-secret", f"{alg} signature verifies with guessable secret '{w}'"); break
        if "exp" not in pay: L.add(rid, "jwt-no-expiry", "token has no exp claim")

def form_checks(L, rid, resp):
    if "html" not in resp.headers.get("Content-Type", "").lower(): return
    for f in re.findall(r"(?is)<form\b[^>]*>.*?</form>", resp.text or ""):
        if not re.search(r"(?i)method\s*=\s*[\"']?post", f): continue
        toks = re.findall(r"(?is)<input\b[^>]*name\s*=\s*[\"'](?:_?csrf\w*|_?xsrf\w*|authenticity_token|_token|nonce|anti-?forgery\w*)[\"'][^>]*>", f)
        if not toks: L.add(rid, "csrf-missing", "HTML POST form without an anti-CSRF token field"); return
        if all(not re.search(r"(?is)value\s*=\s*[\"'][^\"']+[\"']", t) for t in toks): L.add(rid, "csrf-missing", "anti-CSRF token field is present but rendered empty"); return

def sensitive(L, rid, r, resp):
    if is_login(r, []): return
    m = SENS_RE.search(resp.text or "")
    if m: L.add(rid, "sensitive-data-exposure", f"response contains {m.group(0)[:40]}")

def run(L, routes):
    for r in routes:
        rid = f'{r["method"]} {r["path"]} [{r["file"]}::{r["function"]}]'
        if r["file"] == "" and r["function"].startswith("<"): continue
        if r.get("params") and any(p.lower() in {"file", "multipartfile"} for p in r["params"]) and r["method"] == "POST": continue   # multipart upload: not driven here
        keys = param_plan(r); got = baseline(L, r, keys)
        if not got or got[1] is None: L.baselines[rid] = {"status": None}; continue
        m, resp, markers = got; u = url_of(L, r)
        L.baselines[rid] = {"status": resp.status_code, "method": m, "ctype": resp.headers.get("Content-Type", "")}
        if resp.status_code in (404, 405): continue
        analyse_headers(L, rid, resp); check_cors(L, rid, u, m); check_host(L, rid, u, m, markers)
        check_reflection(L, rid, u, m, markers, resp); check_redirect(L, rid, u, m, keys); jwt_checks(L, rid, resp); form_checks(L, rid, resp); sensitive(L, rid, r, resp)
        if re.search(r"(?i)set-cookie", json.dumps(dict(resp.headers))) or resp.cookies: session_checks(L, rid, u, m, markers)
        if is_login(r, keys): login_checks(L, rid, r, u, m)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("base"); ap.add_argument("routes"); ap.add_argument("out")
    ap.add_argument("--ctx", default=""); ap.add_argument("--seed", default=""); ap.add_argument("--budget", type=int, default=900)
    a = ap.parse_args(); L = Live(a.base, a.ctx, a.budget)
    if a.seed: L.req("GET", L.base + a.seed)
    routes = json.load(open(a.routes))["routes"]; t = time.time(); run(L, routes)
    reach = sum(1 for b in L.baselines.values() if b.get("status") not in (None, 404, 405))
    json.dump({"base": a.base, "requests": L.n, "seconds": round(time.time() - t, 1), "routes": len(routes), "reachable": reach, "findings": L.findings, "baselines": L.baselines}, open(a.out, "w"), indent=1)
    c = collections.Counter(f["class"] for f in L.findings)
    print(f"{a.base}: {len(routes)} routes, {reach} reachable, {L.n} requests, {round(time.time()-t,1)}s, findings {dict(c)}")
