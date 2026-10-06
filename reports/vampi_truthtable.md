# VAmPI truth table — end-to-end, honest

VAmPI's own documented list is **6 vulnerabilities** (README). Run through our pipeline as-is
(detection = `pyauto` static; confirmation = the language-neutral HTTP oracles; repair = the
autonomous loop with `codegemma:7b`, local, no cloud). Scored against that 6-item answer key.

| # | Vulnerability (VAmPI's list) | Where | Detect (static) | Confirm (oracle) | Fix (loop, codegemma) |
|---|---|---|---|---|---|
| 1 | Excessive data exposure (`/_debug` leaks passwords) | users.py `debug` | no | **yes** | **PROVEN** |
| 2 | Mass assignment (register as admin) | users.py `register_user` | no | **yes** | not run* |
| 3 | SQL injection (raw f-string query) | user_model.py `get_user` | no† | **yes** (differential) | unresolved‡ |
| 4 | Unauthorized password change (BOLA) | users.py `update_password` | no | **yes** | not run* |
| 5 | BOLA on books (read another user's book) | books.py `get_by_title` | no | **yes** | not run* |
| 6 | Weak JWT signing key (`SECRET_KEY='random'`) | config.py | **yes** | **yes** | not run§ |
| — | (Flask `debug=True`, a 7th misconfig) | app.py | **yes** | n/a | — |

## Score

- **Confirmation: 6 / 6.** Every one of VAmPI's bugs is confirmable with our **unchanged,
  language-neutral oracles** — single-request (data exposure), access-control/metamorphic (mass
  assignment, password change, BOLA), differential (SQLi), and a weak-key metamorphic check (a token
  signed with the guessed `'random'` is accepted, a wrong key is rejected). This is the strong,
  generalising result: verification is complete on a Python app we never built for.
- **Static detection: 1 / 6** (weak JWT, via the hardcoded secret) plus the Flask-debug misconfig.
  The other five are **not static patterns** — they are authz/logic bugs (and the SQLi hides an
  f-string in a variable, needing taint, not a syntactic match). On NodeGoat these same classes
  (IDOR/XSS/CSRF) also needed dynamic probes; for Python those **probe generators are not wired yet**,
  so autonomous *discovery* of the five is the gap.
- **Autonomous repair: 1 proven** (data exposure), and the loop **correctly refused** the SQLi
  patches that broke the app (regression gate held) — no bad fix shipped. The weak model is the
  limit, not safety.

\* not run: the PoV is a multi-step sequence (register-then-act, or two users); the loop's gate
replays a single exploit. Multi-step PoV support is a small extension.
† the SQLi is `execute(text(user_query))` where `user_query` is an f-string variable — taint, not a
syntactic rule, would catch it.
‡ codegemma's patches either crashed the app or changed `get_user`'s return shape (breaking the
normal lookup); all were rejected by the gates.
§ a hardcoded-secret fix (read from env) has no single-request live PoV, so it is `patched_unproven`,
never `proven`.

## Honest takeaway

On a Python/Flask app we never built for: **we can verify every one of its 6 bugs (6/6)**, we
**detect 1 statically**, and we **autonomously fix 1 end-to-end and prove it** — with the loop
rejecting every unsafe patch. The two named gaps are **Python dynamic probe generation** (to
*discover* the authz/logic bugs without being pointed at them) and **multi-step PoV support + a
stronger model** (to fix more of them). Both are known, bounded work; neither is a design flaw.
Verification — the hardest part to generalise — is complete.
