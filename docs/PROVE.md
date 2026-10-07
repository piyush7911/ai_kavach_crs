# AI Kavach — Proof (the PROVE stage)

PROVE is the precision core. A candidate from the FIND stage becomes a reported vulnerability only when a
**replayed exploit fires** or a **deterministic fact is observed** — never because a rule, a scanner, or a
model "thinks" so. This is what lets the system chase broad detection (`docs/DETECTION.md`) while claiming
**zero false positives**: breadth is cheap because nothing is asserted until an oracle confirms it.

## 1. By the numbers

| Asset | Count |
|---|---|
| Oracle mechanisms (self-validating confirmation shapes) | **6** |
| Active probe families | **12** |
| Live HTTP oracle checks | **~12** |
| Vulnerability classes confirmable | **32** |
| — confirmed by a source→HTTP injection/OOB bridge | 11 |
| Reporting-gate required fields (before a finding may be claimed) | **6** |
| Independent FP-safety mechanisms | **7** (see §5) |
| False positives in the claimed tier | **0 by construction** |

## 2. The 6 oracle mechanisms (`benchmarks/oracle_engine.py :: run_exploit`)

`run_exploit(base_url, exploit)` dispatches on the exploit's shape. Each mechanism is *self-validating* — the
success signal cannot be produced by a benign input:

1. **Differential** (`differential`) — SQL/NoSQL injection. A tautology request and a contradiction request;
   confirmed only if their responses differ while a benign control does not. `_norm` strips digits so random
   seed data/timestamps aren't counted as a difference. *A merely reflected input can't flip true vs false.*
2. **Marker** (default `_send` + `success_if`) — command-injection, path-traversal, reflected-XSS,
   open-redirect, SSTI. The success signal is the **result** of the attack, absent from the payload:
   `;expr 31337+1`→`31338`, `../../etc/passwd`→`root:…:0:0`, SSTI `7*191`→`1337`, an unescaped tag reflected
   in an HTML response, the evil host appearing in `Location`. *An echo of the payload never contains the result.*
3. **OOB callback** (`oob`) — SSRF, XXE, insecure-deserialization. The target is induced to fetch a one-time
   loopback listener; a hit proves server-side execution. Loopback-only (air-gap-safe). An LLM may *shape* an
   app-schema payload, but the callback — not the model — decides.
4. **Two-user / metamorphic** (`idor`, `access_control`, `write_idor`) — IDOR, BOLA, broken access control.
   The same request as an authorized vs unauthorized role; or a foreign vs own object id returning different
   data; or verify-after-write (a unique marker written as a non-owner is read back). *A uniform allow/deny
   is never reported.*
5. **Content / behavioral facts** (`live_probes.py`) — headers, cookie flags, CORS, host-header, JWT
   (alg=none / weak secret by wordlist / missing exp), CSRF, rate-limit, enumeration, mass-assignment,
   cache-poisoning, sensitive-data. A fact (a header is absent), a unique-marker read-back (mass-assign,
   cache-poison), a forged-token replay (JWT), or a behavioral count (no lockout after N attempts).
6. **Timing** (`src/pyauto/smuggling.py`) — HTTP request smuggling. Probabilistic, so it is reported only as
   a **candidate** (never `confirmed`), and only on a hang over 2/2 trials past a margin.

12 active families wire these across routes; the live stage adds ~12 HTTP checks.

## 3. Candidate → confirmed bridge (no LLM)

A source-level candidate (file/function/class from static, Opengrep, Joern) is turned into a replayable,
confirmed finding deterministically (`src/pyauto/correlate.py`, `src/pyauto/param_source.py`):

1. map `(file, function)` → the live route, exactly via a framework route map (keyed by `(basename,
   function)`) or heuristically;
2. resolve the HTTP wire parameter from source (constants resolved **file-local-first** — e.g. a Java
   `@RequestParam(Constants.ID)` → `"id"`);
3. run the matching oracle family; promote to `confirmed` only if it fires.

This is how a Joern/Opengrep flag becomes a proven bug with the LLM switched off. Deduplicated by
`(route, param, class)`.

## 4. The reporting gate (structural FP=0) — `src/autonomy/finding_gate.py`

Before any finding may stay `confirmed` (and reach the CSV), it must carry **6** fields, filled *from the
oracle* (not model self-attestation):

1. **poc / exploit** — the replayable request (or a named deterministic fact);
2. **evidence** — the oracle's observation;
3. **counterevidence** — what was controlled for (e.g. "the benign control was not flagged");
4. **confidence** (high|medium|low) + **rationale** when not high;
5. **severity_change_conditions** — one thing that would raise/lower severity;
6. **fix_verification** — required when a patch is attached.

Any finding that cannot satisfy the gate is **downgraded to `candidate`** — a sloppy or unprovable finding
can never be claimed. (Schema adapted from Strix.)

## 5. The 7 FP-safety mechanisms

1. **Benign control leg** in the differential oracle (reflection alone can't flip it).
2. **`_norm`** digit/whitespace stripping (volatile data isn't a difference).
3. **Result-not-payload markers** (31338 / 1337 / `root:…`), impossible to satisfy by echo.
4. **HTML content-type guard** on reflected-XSS (a payload echoed in JSON/text isn't executed → not claimed).
5. **Unique per-attempt markers** for mass-assignment and cache-poisoning (a hit cannot be coincidence).
6. **Loopback-only OOB** + **stability baseline** in parameter discovery (jitter never yields a param).
7. **Candidate sanity** (`candidate_sanity.py`): a static candidate whose cited `file:line`/function does not
   exist is dropped (anti-hallucination); and the **severity-honesty** layer only ever lowers/flags, never
   inflates.

Past example (caught by dogfooding and fixed): the data-exposure oracle once matched an HTML login form's
`name="password"` field; it now requires a real `"key":"value"`, so a form field is never reported as a leak.

## 6. Two-tier output

- **confirmed** — a replayed exploit fired or a deterministic fact was observed; carries a replayable PoC +
  logged HTTP exchange ids. **These are the only claimed vulnerabilities** (the CSV).
- **candidate** — detected but not proven (no oracle for the class, missing auth, timing-only, or
  unconfirmed). Kept in the JSON for transparency, **never asserted**.

Empirically: on NodeGoat the system reports **4 confirmed, 0 false positives**; new oracles (SSTI,
mass-assignment, cache-poisoning, schema-fuzz, GraphQL) return **0** on non-vulnerable targets rather than
guessing — demonstrating they don't false-positive. Real positive confirmations are proven for the
injection, IDOR and live classes (incl. a live SQLi confirmed on DVWA/PHP and SQLi+command-injection on a
Ruby target).

See `docs/ARCHITECTURE.md` (pipeline), `docs/DETECTION.md` (FIND), `docs/PATCH.md` + `docs/VERIFY.md` (fix & proof).
