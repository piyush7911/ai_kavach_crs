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
