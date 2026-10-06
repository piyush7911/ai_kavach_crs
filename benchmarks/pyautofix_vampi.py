"""End-to-end autonomous DISCOVER -> MAP -> FIX -> PROVE on VAmPI, with a local model.

Chains the whole Track-1 pipeline:
  1. dynamic probes discover + confirm bugs on the live app (benchmarks.pyprobe_vampi), each with a
     self-contained, replayable exploit and — via the route's operationId — its handler location;
  2. for every repairable finding, the autonomous repair loop rewrites that one function and the gate
     REPLAYS the same (possibly multi-step) exploit against the patched app: the fix is accepted only
     when the exploit no longer reproduces AND the owner's legitimate use still works.

Nothing here hard-codes a bug location: the file/function come from the discovered finding. Only the
per-class fix guidance and the regression (what "still works" means) are VAmPI-aware, as any per-app
driver is. Mass-assignment is skipped: its proof is not a single-request oracle the gate can replay yet.

    export OPENAI_BASE_URL=http://192.168.0.103:11434/v1 OPENAI_API_KEY=ollama MODEL=codegemma:7b
    python -m benchmarks.pyautofix_vampi
"""
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

from openai import OpenAI

from benchmarks.crosslang_vampi import VAMPI_AUTH
from src.pyauto.probes import ProbeCtx, probe, routes_from_openapi
from src.pyauto.repair import repair

BASE = "http://127.0.0.1:5001"            # the live app, for discovery
SPEC = "benchmark_workspace/VAmPI/openapi_specs/openapi3.yml"
TREE = Path("benchmark_workspace/VAmPI")  # the source the repair loop patches + runs locally
PYBIN = os.environ.get("PYBIN", "/tmp/vampi311/bin/python")
MODEL = os.environ.get("MODEL", "codegemma:7b")
RUN_CMD = PYBIN + " -c \"import config; config.vuln_app.run(host='127.0.0.1', port={port})\""

GUIDANCE = {
    "excessive-data-exposure": "Do not include password, token or secret fields in the response. Return "
        "only non-sensitive fields. Keep the endpoint returning the other data it returned before.",
    "injection": "Do not build the SQL query by concatenating/formatting user input into a string. Use a "
        "parameterized query or the ORM. Preserve the lookup for a legitimate username.",
    "broken-object-level-auth": "Before performing the action, verify the authenticated user is allowed "
        "to act on the target resource (the JWT's user owns it, or is admin). If not, return HTTP 401/403. "
        "Keep the action fully working for the legitimate owner.",
    "user-enumeration": "Return an identical failure response for an unknown username and for a wrong "
        "password, so an attacker cannot tell which usernames exist. Keep a valid login working.",
}


def _seed():
    for attempt in range(4):
        try:
            urllib.request.urlopen(BASE + "/createdb", timeout=10).read()
            return
        except Exception:  # noqa: BLE001
            if attempt == 3:
                raise
            time.sleep(0.5)


def _regression(f):
    """What must still work after the fix (gutting guard), derived from the finding's own exploit."""
    ex = f.exploit
    if "access_control" in ex:                       # BOLA: the legitimate owner can still do it
        ac = ex["access_control"]
        actor, path = ac["authorized"], ac["request"]["path"]
        # a password-change PoV mutates the owner's own password, so logging back in as that owner fails
        # even for a correct fix. Verify the action as admin, whose credential the user-level PoV never
        # touches, on admin's own resource.
        if "password" in path:
            actor, path = "admin", re.sub(r"/users/v1/[^/]+/", "/users/v1/admin/", path)
        reg = {"name": "owner-allowed", "login_as": actor, "auth": VAMPI_AUTH,
               "method": ac["request"]["method"], "path": path,
               "body": ac["request"].get("body"), "expect": {"status_lt": 400}}
        return [reg]
    if f.klass == "injection":                       # a real username still resolves
        return [{"name": "lookup-works", "method": "GET", "path": "/users/v1/name1",
                 "login_as": "none", "auth": VAMPI_AUTH, "expect": {"status": 200, "body_regex": "name1"}}]
    if f.klass == "user-enumeration":                # a valid login still succeeds
        return [{"name": "valid-login", "method": "POST", "path": "/users/v1/login", "login_as": "none",
                 "auth": VAMPI_AUTH, "body": {"username": "name1", "password": "pass1"},
                 "expect": {"status": 200, "body_regex": "auth_token"}}]
    if f.klass == "excessive-data-exposure":         # the listing still returns its non-secret data
        return [{"name": "listing-works", "method": ex["method"], "path": ex["path"], "login_as": "none",
                 "auth": VAMPI_AUTH, "expect": {"status": 200, "body_regex": "name1"}}]
    return []


def _repairable(f):
    replayable = any(k in f.exploit for k in ("access_control", "differential", "success_if"))
    return bool(f.function) and replayable and f.klass in GUIDANCE


def main() -> int:
    if not Path(PYBIN).exists():
        print(f"no Python venv at {PYBIN} (set PYBIN).")
        return 2
    try:
        _seed()
    except Exception as e:  # noqa: BLE001
        print(f"VAmPI not reachable at {BASE} — start it. {e}")
        return 2
    client = OpenAI(base_url=os.environ.get("OPENAI_BASE_URL"), api_key=os.environ.get("OPENAI_API_KEY", "x"))

    def llm(prompt: str) -> str:
        r = client.chat.completions.create(model=MODEL, temperature=0, max_tokens=1024,
                                           messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""

    routes = routes_from_openapi(SPEC)
    findings = probe(routes, ProbeCtx(BASE, VAMPI_AUTH, reseed=_seed))
    repairable = [f for f in findings if _repairable(f)]
    print(f"discovered {len(findings)} bugs; {len(repairable)} repairable with the gate; fixing with {MODEL}\n")

    proven = 0
    for f in repairable:
        finding = {"file": f.file, "function": f.function, "klass": f.klass, "cwe": f.cwe,
                   "guidance": GUIDANCE[f.klass]}
        print(f"-> {f.klass} in {f.file}:{f.function}")
        out = repair(finding, TREE, llm, f.exploit, RUN_CMD, env={"vulnerable": "1"},
                     seed_path="/createdb", health_path="/", regression=_regression(f), attempts=3)
        print(f"   {out.status.upper()} — {out.reason}")
        proven += out.status == "proven"
    print(f"\nautonomously fixed + proven: {proven} / {len(repairable)}")
    return 0 if proven else 1


if __name__ == "__main__":
    sys.exit(main())
