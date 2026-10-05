# Track 1 ↔ Track 2 contract (NodeGoat benchmark)

The interface between the **engine** (`src/jsauto/`, Track 2) and the **harness**
(`benchmarks/nodegoat/`, Track 1). Verified working 2026-10-05: the engine's real
`reports/special/nodegoat_findings.json` scores against this manifest end to end.

## Runner CLI (Track 1 owns; the engine calls it)

    python -m benchmarks.nodegoat.runner start   --tree DIR [--json out]
    python -m benchmarks.nodegoat.runner replay   --tree DIR --exploit E.json [--json out]
    python -m benchmarks.nodegoat.runner regress   --tree DIR [--flows F] [--json out]
    python -m benchmarks.nodegoat.runner score     --findings F --manifest M [--json out]

Exit codes: `replay` 0 = NOT exploitable (fixed/safe), 1 = exploitable, 2 = error.
`regress` 0 = all flows match golden, 1 = diverged, 2 = error. These map directly
onto the DRV loop's `pov_command` (replay) and `test_command` (regress), so the
repair loop wires in with no new gate code:

    pov_command  = python -m benchmarks.nodegoat.runner replay  --tree {tree} --exploit {exploit}
    test_command = python -m benchmarks.nodegoat.runner regress --tree {tree}

Each call runs the tree in isolation: own free port, own Mongo DB (dropped on stop),
loopback only (`loopback_preload.js`), every request throttled.

## Exploit request (either track may emit; `replay` consumes)

    { "method", "path", "headers"?, "body"?, "login_as": "user|admin|none",
      "follow_redirects"?: false,
      "success_if": { "status"?, "body_regex"?, "redirect_regex"?, "oob_marker"? } }

This is exactly the engine's `Finding.exploit` field (`src/jsauto/findings.py`).
When a probe fills `exploit`, the same object goes straight to `replay`.

## Finding (engine emits; `score` consumes)

`src/jsauto/findings.py` `Finding` → `dump()` writes `{"findings": [...], ...}`.
`score` accepts that object or a bare list. It reads `file` (POSIX, relative to the
tree root) and `line`; everything else is ignored by scoring.

## Scoring (Track 1 owns)

`score` matches a finding to a manifest vuln on **file + line proximity only**
(±5 lines; line 0 = whole file, for config/dependencies). It deliberately does NOT
match on class name or CWE, because the two sides use different vocabularies and a
shared vocabulary is not worth enforcing. recall = distinct vulns hit / total;
precision = findings hitting a real vuln / total findings.

Baseline (engine static detection, 2026-10-05): **recall 0.75 (9/12), precision 0.75**. Missed NG-03 (IDOR), NG-06 (XSS), NG-07 (CSRF) — none is
statically detectable; they need the engine's dynamic probes (2.3), which emit an
`exploit` that `replay` then confirms.

## Open decisions, with Track 2's answers (2026-10-05)

Status: **ANSWERED** = decided and implemented or ready to implement; **NEEDS ORGANISERS** = we cannot
decide it from the code.

### 1. Do seeded test credentials and dev/test config secrets count as defects?  ANSWERED: no, report them as informational

They are real hard-coded credentials, but a password in a seed script or in `development.js` is not a
production secret, and counting it as a defect would be scored as noise by anyone reading the report.
Hiding it would be worse, because a reviewer should still see it. So:

- The engine now tags a `hardcoded-secret` found in a test, seed, fixture, example or local-development
  file as `status: "informational"`, `severity: "low"`, with a reason. Decided on the file's **role**
  (directory such as `test/`, `seeds/`; stem such as `development.js`, `test.js`; name containing
  `seed`/`reset`/`fixture`/`migrate`), never on this application's file names. Implemented in
  `src/jsauto/static.py` (`_mark_non_production`) with unit tests.
- **A committed private key is never downgraded this way.** A key in a repository is exposed whatever the
  file is called (`artifacts/cert/server.key` stays NG-09).
- **Track 1 action:** make `score` skip findings whose `status` is `informational` or `suppressed` when
  computing precision (they stay in the output). Keep them out of the manifest.

### 2. Is the session-cookie weakness (`server.js:78`) its own vuln?  ANSWERED: yes, add NG-12

Verified in the code: the session middleware is configured with only `secret`, `saveUninitialized`
and `resave`; the block that sets a generic cookie name and the cookie flags is **commented out**
("Fix for A5 - Security MisConfig"). So the cookie has the default name and no `httpOnly`, `secure`,
`path` or `expires` attributes. That is a different defect from the hard-coded secret: different
weakness (CWE-614 / CWE-1004 / CWE-16 against CWE-798), a different fix (set cookie options, not move a
secret), and a different probe (inspect `Set-Cookie`). Folding it into NG-08 would hide a fix the jury
can see.

Proposed manifest entry: `NG-12`, `owasp: A5` (security misconfiguration), `cwe: CWE-1004`,
`class: insecure-session-cookie`, `kind: config`, `file: server.js`, `line: 78`,
`validation: inspection` (a PoV is easy: read `Set-Cookie` after login and check the attributes).

### 3. Is querying the npm registry allowed at the event?  NEEDS ORGANISERS (assume NO until told)

The rules allow only our own hardware, authorised software stacks and declared model endpoints, and
list "unauthorized public or external network resources" as out of scope. The npm registry is
external and was not declared, so the safe default is **not allowed**. Two consequences:

- **Detection:** `npm audit` needs the registry. Until we have an answer, the engine must not rely on
  it. Plan: ask the organisers one yes/no question at check-in. If the answer is no, build a **vendored
  advisory snapshot** before the event (advisory data for npm packages, filtered to the versions that
  popular apps pin), and match the lockfile against it offline. Size and coverage of that snapshot are
  **not measured yet**; do not promise it covers an unseen app's dependencies.
- **Running the target:** `npm install` also hits the registry. If the venue has no outbound access, the
  target's `node_modules` must be pre-installed or provided. That is Track 1's setup question too.
- Whatever is decided, a failed audit already says so loudly and never reports an empty "clean" list.

### 4. IDOR / XSS / CSRF  ANSWERED: Track 2 owns them; here is how, generically

They stay `validation: inspection` until a probe confirms them. None needs an application-specific rule:

- **CSRF (NG-07):** partly detectable statically with a general rule: the app uses cookie sessions, has
  state-changing routes (POST/PUT/PATCH/DELETE), and imports no CSRF-protection module. Low confidence
  until a probe shows a state-changing request is accepted without a token or from a foreign `Origin`.
  Will be added to the engine.
- **XSS (NG-06):** needs a reflection probe: submit a unique canary through each input the flow analysis
  found, read the pages back, and check whether it returns unencoded in a script/attribute/URL context.
  Needs the runner (Track 1 runtime), so it waits for it.
- **IDOR (NG-03):** needs authorisation-aware probing: with two seeded users, request user B's resource
  as user A using ids taken from routes that accept an id. Also needs the runner and two users.

All three emit an `exploit` in the contract's format, which `replay` then confirms.

## Review notes on scoring (Track 2's reading of `score`)

Measured with the current engine against the current manifest: **recall 0.727 (8/11), precision 0.81**,
missed NG-03, NG-06, NG-07, unchanged from the baseline above.

1. **Precision is inflated by dependency findings.** The 21 findings include 10 separate
   vulnerable-dependency findings (one per package), and every one lands on `package.json` line 0, so all
   10 count as true positives against the single manifest entry NG-11. Without them, the other 11
   findings have 7 hits, which is **0.64**, not 0.81. Recall is not affected. Suggest counting findings
   of the same class and file as one for precision, or reporting dependency findings separately.
2. **Matching ignores class by design,** so a wrong-class finding near a manifest line counts as a hit.
   That is acceptable while the engine is the only finding source, but say so in any published number.
3. **Projected, not re-scored:** with decisions 1 and 2 applied (informational findings excluded, NG-12
   added) and dependency findings counted once, the same output would give recall 9/12 = 0.75 and no
   false positives on this target. That is arithmetic from the current output, not a new run.
4. **Overfitting caution.** These numbers are on the application the engine was developed against. On a
   second, unseen app (DVNA, no tuning, no model) 5 of 6 core injection classes were found by some
   detector and 3 of 6 by the flow analysis alone; see "Held-out check" in `NODEGOAT_PLAN.md`. That is
   the better indicator of how it will do on the jury's customised app.

---

## Track 1 responses (implemented 2026-10-05)

All of Track 2's asks above are done on the harness side:

1. **Informational/suppressed findings** are excluded from precision (kept in the output and
   counted separately as `informational_excluded`). `score` reads `status`.
2. **Dependency inflation fixed.** Precision now groups findings by `(file, class)`, so the N
   vulnerable-dependency findings on `package.json` count once. `score` reports `finding_groups`.
3. **NG-12 added** to the manifest (insecure-session-cookie, server.js:78). It is `validation: both`,
   not inspection: `povs/ng_session_cookie.json` confirms the default `connect.sid` cookie name on the
   vulnerable tree and flips safe once a generic `name` is set. Added a `set_cookie_regex` oracle.
4. **IDOR / XSS / CSRF reference PoVs already exist** for the probes to reproduce:
   `povs/ng_idor_allocations.json`, `povs/ng_xss_stored.json`, `povs/ng_csrf.json` — all in the
   contract's exploit shape, all confirmed exploitable via `replay`. SSRF too
   (`povs/ng_ssrf.json`, via the OOB marker server). The exploit model now also supports `setup`
   steps (store-then-read) and `oob` (loopback marker server).

**Current score** (engine static detection vs the 12-vuln manifest): **recall 0.75 (9/12),
precision 0.75**, rising to precision ~1.0 once the engine re-runs with informational tagging (the
committed findings file predates it). Missed NG-03/06/07 — the three dynamic-probe classes.

**npm/offline (decision 3):** `setup.sh` runs `npm install` against the registry today. For an
air-gapped venue the target's `node_modules` must be pre-installed or provided; noted as a Track 1
setup item.

---

## Hardening (variants) — Track 1, added 2026-10-05

The web analogue of re-fuzzing a C patch: replay alternate encodings of the same attack
after a patch passes PoV+regress. A correct fix defeats all; an overfitted fix that only
special-cases the primary input leaks a variant.

    python -m benchmarks.nodegoat.runner harden --tree DIR --id NG-04 [--json out]

Exit: 0 hardened, 1 overfitted, 2 vulnerable/error. Reads the vuln's `pov` + `variants`
from the manifest, runs them against one app instance, verdict:
- **vulnerable** — primary PoV still exploitable (patch did not fix it)
- **overfitted** — primary safe but a variant still exploitable
- **hardened** — primary and every variant safe

Verified three-way on NG-04 (open redirect): vulnerable tree → vulnerable; a normalising
fix → hardened; a fix that only blocks the literal `evil.example.com` host → overfitted
(leaks the different-host variant). Variants added for NG-01 eval (2), NG-02 NoSQL (2),
NG-03 IDOR (1), NG-04 redirect (2), NG-06 XSS (1); each confirmed exploitable on the
vulnerable tree. The engine's hardening step can call `harden`, or replay the manifest's
`variants` directly (same exploit shape as `replay`).
