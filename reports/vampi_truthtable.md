# VAmPI truth table — end-to-end, honest

VAmPI's own documented list is **9 vulnerabilities** (README). Run through our pipeline as-is:
detection = `pyauto` static; confirmation = the language-neutral HTTP oracles; repair = the
autonomous loop with `codegemma:7b` (local, no cloud). Scored against that 9-item answer key.

| # | Vulnerability (VAmPI's list) | Where | Detect (static) | Confirm (live oracle) | Fix (loop) |
|---|---|---|---|---|---|
| 1 | SQL injection | user_model.py `get_user` | no† | **yes** (differential) | unresolved‡ |
| 2 | Unauthorized password change (BOLA) | users.py `update_password` | no | **yes** (metamorphic) | not run* |
| 3 | Broken Object Level Authorization | books.py `get_by_title` | no | **yes** (metamorphic) | not run* |
| 4 | Mass assignment | users.py `register_user` | no | **yes** | not run* |
| 5 | Excessive data exposure (`/_debug`) | users.py `debug` | no | **yes** | **PROVEN** |
| 6 | User & password enumeration | users.py `login_user` | no | **yes** (different login errors) | not run* |
| 7 | RegexDOS (denial of service) | users.py `update_email` | no§ | inspection only¶ | not run |
| 8 | Lack of resources & rate limiting | all endpoints | no | **yes** (no 429 under load) | not run** |
| 9 | JWT bypass via weak signing key | config.py `SECRET_KEY` | **yes** | **yes** (weak-key accepted, wrong-key rejected) | not run§§ |
| — | (Flask `debug=True`, a bonus misconfig) | app.py | **yes** | n/a | — |

## Score

- **Confirmation: 8 / 9 live** (all except RegexDOS, which we deliberately do not DoS-test). Every
  confirmed bug uses our **unchanged, language-neutral oracles** — single-request, differential
  (SQLi), metamorphic (BOLA / password-change / enumeration / access-control), a weak-key check, and
  a rate-limit check. **Verification generalises to a Python app we never built for.**
- **Static detection: 1 / 9** (weak JWT, via the hard-coded secret) plus the Flask-debug misconfig.
  The rest are authz/logic/behaviour bugs that reading code cannot see; on NodeGoat the same classes
  needed dynamic probes. For Python those **probe generators are not wired yet**, so autonomously
  *discovering* the other eight is the gap (RegexDOS is the one that a future static ReDoS rule could
  also catch).
- **Autonomous repair: 1 proven** (data exposure), and the loop **refused** every SQLi patch that
  broke the app (regression gate held). No bad fix shipped — the weak model is the limit, not safety.

\* not run: the PoV is a multi-step sequence (register-then-act, two users, or before/after login);
the loop's gate replays a single exploit. Multi-step PoV support is a small extension.
† SQLi is `execute(text(user_query))` where `user_query` is an f-string variable — taint, not a
syntactic rule, catches it.
‡ codegemma's patches crashed the app or changed `get_user`'s return shape; the gates rejected all.
§ RegexDOS is static-detectable in principle (a nested-quantifier regex); no rule written yet.
¶ a live ReDoS PoV is a denial of service, which the Rules of Engagement forbid — inspection only.
\** rate limiting is a cross-cutting fix (middleware), not a single-function rewrite.
§§ a hard-coded-secret fix (read from env) has no single-request live PoV, so it is at best
`patched_unproven`, never `proven`.

## Honest takeaway

On a Python/Flask app we never built for, with VAmPI's own 9-item list: **verify 8/9 live**
(RegexDOS excluded by the rules), **detect 1/9 statically**, and **autonomously fix 1 end-to-end and
prove it** — with every unsafe patch rejected. The named gaps are **Python dynamic probe generation**
(to *discover* the authz/logic bugs without being pointed at them), **multi-step PoV support**, and
**a stronger model** (to fix more). All bounded, known work. Verification — the hardest part to
generalise — carries over almost completely.
