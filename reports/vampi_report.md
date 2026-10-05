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
