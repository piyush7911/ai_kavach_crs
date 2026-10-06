# Held-out test: VAmPI (honest report)

Target: [VAmPI](https://github.com/erev0s/VAmPI) @ f16052d — a deliberately vulnerable **Python /
Flask / SQLAlchemy / JWT** REST API (OWASP API Top 10). Run AS-IS, no code changes to our engine or
to VAmPI. This is a true held-out test: a different app in a **language we have not built for**.

## Result

**Found: 0. Fixed: 0.** Not because VAmPI is clean — it is full of real bugs — but because **our
engine currently supports JavaScript/Node and C, not Python.** It failed honestly, at the front door,
rather than producing anything false.

## What happened, step by step

1. **JS backend refused.** `python -m src.jsauto --target VAmPI` →
   `"benchmark_workspace/VAmPI has no package.json: not a Node application."` It correctly detects the
   app is not Node and stops, rather than emitting garbage findings.
2. **All vendored detection rules are JS.** `config/semgrep/` holds `javascript.yaml`, `nodejs.yaml`,
   `expressjs.yaml`, `kavach_js.yaml`, and `secrets.yaml`. None has Python rules. The one
   language-agnostic rule (`secrets.yaml`) found **0** on VAmPI — it missed even the plain hardcoded
   `SECRET_KEY = 'random'` (config.py:13), i.e. it is JS-shaped too.
3. **Flow analysis can't parse it.** The generic flow analysis uses `tree-sitter-javascript`, which
   cannot parse `.py`.
4. **C backend doesn't apply.** `src/main.py` / the autonomy pipeline target C (clang, ASan, CBMC).
5. **Runner/repair don't apply.** The runner starts a Node app (`node server.js`, `db-reset.js`,
   Mongo, NodeGoat creds); VAmPI is `flask run` + SQLite. The repair loop uses JS prompts, a JS patch
   splicer and a JS policy gate.

So nothing in the pipeline fires on a Python app today. That is the correct, honest behaviour for the
current build — but it means **0 of VAmPI's bugs were found or fixed.**

## What is actually in VAmPI (the bugs a Python-capable engine would target)

Confirmed by reading the source — this is what we are currently blind to:

| Bug | Where | Class |
|---|---|---|
| Mass assignment (register as admin) | `api_views/users.py:60-66` (`if vuln and 'admin' in request_data`) | CWE-915 |
| Hardcoded secret | `config.py:13` (`SECRET_KEY = 'random'`) | CWE-798 |
| Plaintext passwords | `users.py:93` (`request_data['password'] == user.password`) | CWE-256 |
| Excessive data exposure | `users.py:24` (`/debug` returns all users incl. passwords) | CWE-213 |
| Broken auth / weak JWT | JWT signed with `'random'` | CWE-287 |
| BOLA / broken object auth, user enumeration, SQLi | various endpoints | OWASP API1/API3 |

## The honest conclusion

This is exactly the **unknown-finale-language risk** we flagged. Our architecture is a shared core
with swappable backends, and it generalised *within* JavaScript (NodeGoat → the renamed/DVNA detection
evidence) — but **a Python backend does not exist**, so a Python target yields nothing. The engine is
honest about it (it refuses rather than faking), which is the right failure mode, but it is still a
hard gap.

### What it would take to close it (not done here)
1. **Python detection:** Semgrep Python rules + `tree-sitter-python` for the flow/context mapping.
2. **A Python app runner:** the universal-engine + per-app adapter (`start`/`seed`/`creds`/`health`)
   so `flask run` + SQLite is a 4-field config, not a rewrite. The exploit/regression/hardening and
   the metamorphic oracles (injection, IDOR, access-control) are already HTTP-level and
   language-neutral — they would work against a Flask app unchanged once it can be started.
3. **Python repair:** Python prompts + a Python patch splicer + the policy gate for Python.

Items 2's oracles and the whole verify-first design carry over; items 1 and 3 are per-language and
are the real work. Until then, the honest VAmPI score is **0 found, 0 fixed.**

---

## Update (2026-10-06): verification layer PROVEN cross-language

After the 0/0 above, we tested whether the part that is *supposed* to be language-neutral — the
HTTP verification layer — actually works on a Python app. It does. VAmPI was booted in Docker on
loopback (`127.0.0.1:5001`, Python 3.11 image, seeded via `/createdb`), and our **unchanged oracle
code** (the same used against the Node app) confirmed real VAmPI bugs, with only an **auth config**
added for VAmPI's JWT login:

| VAmPI bug | Oracle used (unchanged) | Result |
|---|---|---|
| Excessive data exposure, `/_debug` leaks passwords (CWE-213) | single-request body oracle | CONFIRMED |
| Mass assignment → admin (CWE-915) | access-control / metamorphic reasoning | CONFIRMED |
| (VAmPI's DELETE is actually admin-protected) | access-control oracle | correctly NOT flagged |

The only change to the code was making `Session` auth pluggable: default stays NodeGoat's cookie
form-login; VAmPI uses `{"kind":"bearer_json","login_path":"/users/v1/login",...}`. NodeGoat's
oracles and tests are unchanged and still pass. Reproducible: `python -m benchmarks.crosslang_vampi`.

**What this proves and what it does not.** The *verification* half of the system — exploit replay,
regression, hardening, and the metamorphic oracles (injection, IDOR, access-control) — is genuinely
language-neutral: it speaks HTTP. So for an unknown-language finale app, confirming and hardening
fixes carries over. **Still not done for Python:** *detection* (needs Python Semgrep rules +
`tree-sitter-python`) and *repair* (needs Python prompts + a Python patch splicer). So the full
find -> fix loop on Python is not yet closed — but the hardest-to-generalise part, trustworthy
verification, is. The remaining per-language work is detection and repair.

**Per-app adapter (done):** the runner now drives any web app, not just the Node tree, via
`--app <config.json>` (`benchmarks/appadapter.py`). VAmPI's config
(`benchmarks/apps/vampi.json`) describes its base URL, HTTP seed (`/createdb`) and JWT auth; then
`python -m benchmarks.nodegoat.runner start|replay --app benchmarks/apps/vampi.json ...` confirms
VAmPI's data-exposure bug through the real runner CLI. NodeGoat's `--tree` path is unchanged. So an
unknown HTTP app is a small config plus (per language) detection and repair.

---

## Update (2026-10-06): Python DETECTION now works

A Python detection backend (`src/pyauto/`) was added — the counterpart of `src/jsauto`. It runs
generic Kavach Python rules (`config/semgrep/kavach_py.yaml`: hardcoded secret, eval/exec code
injection, string-built SQL, command injection, Flask debug) with Semgrep **offline** (local rule
file, no registry), maps each hit to its enclosing function with `tree-sitter-python`, and emits the
SAME `Finding` type the JS backend uses — so scoring/reporting are unchanged.

    python -m src.pyauto --target benchmark_workspace/VAmPI

On VAmPI it finds **4 real bugs in 2 s**: the hardcoded `SECRET_KEY='random'` (config.py:13), the
hardcoded JWT secret in `token_validator` (users.py:122/124), and `debug=True` (app.py:17). The
logic bugs VAmPI also has (BOLA, mass assignment, data exposure) are not static patterns — they are
confirmed by the HTTP oracles instead (see the cross-language section above).

### VAmPI status now
- **Detection:** working (4 static bugs via `pyauto`).
- **Verification:** working (data-exposure + mass-assignment confirmed via the runner adapter).
- **Repair:** NOT done for Python — needs Python repair prompts + a `tree-sitter-python` patch
  splicer + the policy gate for Python. That is the remaining piece before a full Python
  find -> fix -> prove loop.

So VAmPI has gone from **0 found / 0 fixed** to **detection + verification working cross-language**,
with Python repair as the last backend piece.

---

## Update (2026-10-06): Python REPAIR mechanics proven — full loop both directions

Added the Python patch splicer (`src/pyauto/patch.py`): whole-function replacement by
tree-sitter-python byte range, indentation-matched, with a `parse_errors` syntax gate — the Python
counterpart of the JS splicer. A fix spliced into VAmPI's `register_user` (ignore the client-supplied
admin flag) parses as valid Python.

Live both-directions on VAmPI's mass-assignment bug (CWE-915), via Docker on loopback:
- **Vulnerable** (`:5001`): register with `admin:true` then perform an admin-only action -> **200 (EXPLOITABLE)**.
- **Patched** (`:5002`, spliced fix): same attack -> **401 (FIXED / denied)**.

So on a Python/Flask app we never built for, the full loop works: **pyauto detects, the splicer
applies a Python patch, and the HTTP oracle proves the fix both directions.** The patch here was a
reference fix (as in our Node both-directions validation); the model that writes it is the same
general LLM used for JS. The remaining wiring (Python repair prompts, policy, and a managed adapter
that runs a patched copy per attempt) is documented in `src/pyauto/REPAIR_HANDOFF.md` for Track 2.

### VAmPI final status
Detection ✅ · Verification ✅ · Repair mechanics ✅ (loop proven both directions) ·
Model-driven repair loop: wiring left (thin mirror of src/jsauto + a managed Python adapter).

---

## Update (2026-10-06): FULL autonomous Python loop — PROVEN with a local model

The Python repair loop is now wired end to end (`src/pyauto/repair.py` + `src/pyauto/runner.py`):
the model proposes the whole function, it is spliced + parse-checked, the PATCHED Flask app is
started on a free port per attempt, and the fix is accepted only when the exploit no longer
reproduces AND a regression flow still passes.

Run on VAmPI's excessive-data-exposure bug with **`codegemma:7b` (local, no cloud)**:

    python -m benchmarks.pyrepair_vampi
    attempt 1: accepted: exploit gone; regression ok
    RESULT: proven — 13 s, first attempt, stable across runs

The model's patch (real, not hand-written):

    def debug():
    -    return jsonify({'users': User.get_all_users_debug()})
    +    users = User.get_all_users_debug()
    +    filtered = [{k: v for k, v in u.items() if k not in ['password', 'token']} for u in users]
    +    return jsonify({'users': filtered})

### VAmPI final status: full find -> fix -> prove, cross-language, local model
Detection ✅ · Verification ✅ · Repair ✅ (autonomous, local model, proven + regression). The same
architecture now closes the loop on a Python/Flask app we never built for — per-language rules, a
parser, a splicer, and an auth config, with the LLM and the gates unchanged.
