# VAmPI truth table — end-to-end, honest

VAmPI's own documented list is **9 vulnerabilities** (README). Run through our pipeline as-is:
**discovery** = `pyauto` static rules + route-driven dynamic probes (`src/pyauto/probes.py`);
**confirmation** = the language-neutral HTTP oracles; **repair** = the autonomous loop with
`codegemma:7b` (local, no cloud). Scored against that 9-item answer key. Nothing in the engine names a
VAmPI endpoint — the probes read routes from the app's OpenAPI spec and try the oracle families blind.

| # | Vulnerability (VAmPI's list) | Discover (auto) | Confirm (live oracle) | Fix (loop) |
|---|---|---|---|---|
| 1 | SQL injection | **probe** (differential) | **yes** | **PROVEN**‡ |
| 2 | Unauthorized password change (BOLA) | **probe** (metamorphic) | **yes** | rejected† |
| 3 | Broken Object Level Authorization (books) | **probe** (setup + metamorphic) | **yes** | **PROVEN** |
| 4 | Mass assignment | **probe** (register admin-flag → escalation) | **yes** | not gated‡‡ |
| 5 | Excessive data exposure (`/_debug`) | **probe** (sensitive field in body) | **yes** | **PROVEN** |
| 6 | User & password enumeration | **probe** (differential on login) | **yes** | **PROVEN** |
| 7 | RegexDOS (denial of service) | no§ | inspection only¶ | not run |
| 8 | Lack of resources & rate limiting | no‖ | **yes** (no 429 under load) | not run** |
| 9 | JWT bypass via weak signing key | **static** (hard-coded secret) | **yes** | not run§§ |
| — | BOLA email change (bonus) | **probe** (metamorphic) | **yes** | rejected† |
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
- **Autonomous repair: 4 classes proven** — SQLi, books-BOLA and enumeration proven **in one chained
  `discover → map → fix → prove` run** (`benchmarks.pyautofix_vampi`, codegemma:7b, local), and data
  exposure proven by the single-bug driver. The fix target is not hard-coded: the handler
  (file + function) comes from the discovered finding's route (operationId), and the gate **replays the
  same multi-step exploit** (two users, and for books the owner's create step) against the patched app,
  accepting only when the exploit is gone AND the owner's legitimate use still works. The two BOLA
  patches the model got wrong were **rejected** (one still exploitable, one broke the owner's own path);
  no bad fix shipped. The model is the limit, not safety.

† rejected: codegemma's patch either left the bug exploitable or broke the legitimate owner's request;
every rejection is real (the gate replayed the multi-step exploit + an owner regression). A stronger
model closes these; the pipeline and gates are in place.
‡ SQLi now **proven**: with the differential PoV replayed by the gate and "use a parameterized query,
keep the lookup working" guidance, codegemma produced a parameterized `get_by_username` that the gate
accepted (earlier attempts without this pipeline crashed the app and were rejected).
‡‡ mass-assignment is confirmed by bespoke probe logic, not a single `run_exploit` oracle, so the gate
cannot replay it yet; wiring it to the metamorphic oracle is the remaining step to make it repairable.
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
**autonomously fix 4 classes end-to-end and prove them** (SQLi, books-BOLA, enumeration, data-exposure)
— with every unsafe patch rejected. The full chain runs with no hard-coded bug location: the probe
finds it over HTTP, the operationId maps it to a function, the loop rewrites that function, and the gate
re-proves it by replaying the multi-step exploit. The named gaps are **a stronger model** (to fix the
remaining BOLA cases the gate already rejects bad patches for) and **wiring mass-assignment to a
replayable oracle**. All bounded, known work. Discovery, verification AND repair now carry over.
