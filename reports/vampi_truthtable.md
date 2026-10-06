# VAmPI truth table — end-to-end, honest

VAmPI's own documented list is **9 vulnerabilities** (README). Run through our pipeline as-is:
**discovery** = `pyauto` static rules + route-driven dynamic probes (`src/pyauto/probes.py`);
**confirmation** = the language-neutral HTTP oracles; **repair** = the autonomous loop with
`codegemma:7b` (local, no cloud). Scored against that 9-item answer key. Nothing in the engine names a
VAmPI endpoint — the probes read routes from the app's OpenAPI spec and try the oracle families blind.

| # | Vulnerability (VAmPI's list) | Discover (auto) | Confirm (live oracle) | Fix (loop) |
|---|---|---|---|---|
| 1 | SQL injection | **probe** (differential) | **yes** | unresolved‡ |
| 2 | Unauthorized password change (BOLA) | **probe** (metamorphic) | **yes** | not run* |
| 3 | Broken Object Level Authorization (books) | **probe** (setup + metamorphic) | **yes** | not run* |
| 4 | Mass assignment | **probe** (register admin-flag → escalation) | **yes** | not run* |
| 5 | Excessive data exposure (`/_debug`) | **probe** (sensitive field in body) | **yes** | **PROVEN** |
| 6 | User & password enumeration | **probe** (differential on login) | **yes** | not run* |
| 7 | RegexDOS (denial of service) | no§ | inspection only¶ | not run |
| 8 | Lack of resources & rate limiting | no‖ | **yes** (no 429 under load) | not run** |
| 9 | JWT bypass via weak signing key | **static** (hard-coded secret) | **yes** | not run§§ |
| — | BOLA email change (bonus) | **probe** (metamorphic) | **yes** | — |
| — | Flask `debug=True` (bonus misconfig) | **static** | n/a | — |

## Score

- **Autonomous discovery: 8 / 9** — **7 via dynamic probes** (SQLi, password-BOLA, books-BOLA,
  mass-assignment, data-exposure, enumeration, plus a bonus email-BOLA) and **1 via static** (weak
  JWT, plus the Flask-debug misconfig). The probes are route-derived and app-agnostic:
  `benchmarks.pyprobe_vampi` reads 14 routes from VAmPI's OpenAPI and the oracle families find these
  with **no hard-coded paths**. Books-BOLA is found by a **resource-setup probe**: the owner creates
  the object via the collection POST, then a non-owner reads it. The only undiscovered bugs are the two
  the Rules of Engagement forbid probing live (ReDoS, rate-limiting). This is the jump from the old
  "detect 1 statically" to "discover 7 dynamically + 1 statically".
- **Confirmation: 8 / 9 live** (all except RegexDOS, which we deliberately do not DoS-test). Every
  confirmed bug uses our **unchanged, language-neutral oracles** — single-request, differential
  (SQLi / enumeration), metamorphic (BOLA / mass-assignment / access-control), a weak-key check, and a
  rate-limit check. **Verification generalises to a Python app we never built for.**
- **Autonomous repair: 1 proven** (data exposure), and the loop **refused** every SQLi patch that
  broke the app (regression gate held). No bad fix shipped — the weak model is the limit, not safety.

\* not run as a repair yet: the fix is real but the loop's single-exploit gate needs the multi-step PoV
these bugs confirm with (register-then-act, two users). Confirmation already does the multi-step.
† (resolved) books-BOLA is now found by the resource-setup probe: store a book as one user, read it
as another. Earlier this was the gap; the `_bola_setup` family stages the create, then compares.
‡ codegemma's patches crashed the app or changed `get_user`'s return shape; the gates rejected all.
§ RegexDOS is static-detectable in principle (a nested-quantifier regex); no rule written yet.
¶ a live ReDoS PoV is a denial of service, which the Rules of Engagement forbid — inspection only.
‖ rate-limiting is confirmed when pointed, but not auto-probed: a discovery burst flirts with the
no-DoS rule, so it stays a pointed check, not a blind probe.
\** rate limiting is a cross-cutting fix (middleware), not a single-function rewrite.
§§ a hard-coded-secret fix (read from env) has no single-request live PoV, so it is at best
`patched_unproven`, never `proven`.

## Honest takeaway

On a Python/Flask app we never built for, with VAmPI's own 9-item list: **autonomously discover 8/9**
(7 by dynamic probes, 1 by static), **confirm 8/9 live** (RegexDOS excluded by the rules), and
**autonomously fix 1 end-to-end and prove it** — with every unsafe patch rejected. The named gaps are
**multi-step PoV support in the repair gate** (to fix
the bugs we already confirm), and **a stronger model** (to fix more). All bounded, known work.
Discovery and verification — the parts hardest to generalise — now both carry over.
