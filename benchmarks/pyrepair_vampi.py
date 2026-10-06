"""Autonomous Python find->fix->prove on VAmPI, end to end with a local model.

Needs: VAmPI source at benchmark_workspace/VAmPI, a Python 3.11 venv with its deps (PYBIN), and an
OpenAI-compatible model endpoint (env). Runs the repair loop on the data-exposure bug: the model
rewrites the `debug` handler, the patched Flask app is started per attempt, and the fix is accepted
only when the exploit (passwords in /_debug) no longer reproduces and the normal user listing still
works.

    export OPENAI_BASE_URL=http://192.168.0.103:11434/v1 OPENAI_API_KEY=ollama MODEL=codegemma:7b
    python -m benchmarks.pyrepair_vampi
"""
import os
import sys
from pathlib import Path

from openai import OpenAI
from src.pyauto.repair import repair

PYBIN = os.environ.get("PYBIN", "/tmp/vampi311/bin/python")
MODEL = os.environ.get("MODEL", "codegemma:7b")
TREE = Path("benchmark_workspace/VAmPI")

AUTH = {"kind": "bearer_json", "body_json": True, "login_path": "/users/v1/login",
        "user_field": "username", "pass_field": "password", "token_field": "auth_token",
        "roles": {"admin": ["admin", "pass1"], "user": ["name1", "pass1"]}}

FINDING = {
    "file": "api_views/users.py", "function": "debug", "klass": "excessive-data-exposure",
    "cwe": "CWE-213",
    "guidance": "A debug/listing endpoint must not return secrets. Do not include password or token "
                "fields in the response; return only non-sensitive fields.",
}
# the exploit: /_debug currently leaks passwords. exploitable while a "password" field is present.
POV = {"method": "GET", "path": "/users/v1/_debug", "login_as": "none",
       "success_if": {"status": 200, "body_regex": '"password"'}, "auth": AUTH}
# the normal listing must still work (don't "fix" by breaking the endpoint entirely)
REGRESSION = [{"name": "users-list", "method": "GET", "path": "/users/v1", "login_as": "none",
               "expect": {"status": 200, "body_regex": "name1"}}]

RUN_CMD = PYBIN + " -c \"import config; config.vuln_app.run(host='127.0.0.1', port={port})\""


def main() -> int:
    if not Path(PYBIN).exists():
        print(f"no Python venv at {PYBIN} (set PYBIN). Create: python3.11 -m venv ...; pip install -r {TREE}/requirements.txt")
        return 2
    client = OpenAI(base_url=os.environ.get("OPENAI_BASE_URL"), api_key=os.environ.get("OPENAI_API_KEY", "x"))

    def llm(prompt: str) -> str:
        r = client.chat.completions.create(model=MODEL, temperature=0,
                                           messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""

    print(f"repairing {FINDING['klass']} in {FINDING['file']}:{FINDING['function']} with {MODEL} ...")
    out = repair(FINDING, TREE, llm, POV, RUN_CMD, env={"vulnerable": "1"},
                 seed_path="/createdb", health_path="/", regression=REGRESSION, attempts=3)
    for a in out.attempts:
        print(f"  attempt {a['n']}: {a['stage']}: {a['detail'][:90]}")
    print(f"RESULT: {out.status} — {out.reason}")
    if out.diff:
        print("--- patch ---")
        print(out.diff)
    return 0 if out.status == "proven" else 1


if __name__ == "__main__":
    sys.exit(main())
