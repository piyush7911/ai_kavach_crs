# AI Kavach — Verification (proof a finding is real and a fix holds)

Verification is what makes both halves trustworthy: every **claimed vulnerability** carries a replayable
proof, and every **applied fix** is gated so it provably removes the bug *and* preserves behaviour. Nothing
is taken on a model's word, and every run leaves a complete audit trail. This is the system's answer to the
"regression proof" and auditability requirements.

## 1. By the numbers

| Asset | Count |
|---|---|
| Patch-acceptance gate stages | **4** (PoV-gone · regression · static re-scan · sibling review) |
| Regression set source | **observed traffic** (derived, never model-invented) |
| Audit artifacts written per run | **6** |
| Coverage-ledger outcomes (evidenced negative space) | **5** |
| Outcomes requiring evidence | **3** (ruled_out / not_applicable / needs_follow_up) |
| Fabricated HTTP-evidence ids accepted | **0** (`verify()` rejects unknown ids) |

## 2. Verifying a finding is real (confirmation side)

Every `confirmed` finding carries:
- a **replayable exploit** (`exploit` dict) — the exact request(s) `run_exploit` sends;
- an **evidence** record — the oracle's observation (differential flip, marker result, OOB hit, two-user diff);
- **logged HTTP exchange ids** (`exchanges.jsonl`) — the actual attack traffic, numbered. `verify()`
  (`src/autonomy/exchange_log.py`) rejects any cited id the log never recorded, so "confirmed by a live
  exploit" is an independently queryable claim, not a code assertion.

The reporting gate (`src/autonomy/finding_gate.py`, see `docs/PROVE.md`) blocks any finding that cannot carry
poc/evidence/counterevidence/confidence/severity-conditions — downgrading it to `candidate`. So the claimed
set is verifiable by construction.

## 3. Verifying a fix holds (the 4-way patch gate)

A patch (template or LLM) is accepted only if **all four** pass:

1. **PoV-gone** — the exploit that confirmed the bug is replayed against the **patched build** and must no
   longer fire. (fail → the attacking request is fed back as a counterexample, CEGIS.)
2. **Regression / behaviour preserved** (`src/autonomy/differential_validation.py`) — the regression set is
   **derived from observed traffic**: the app's own reachable routes are replayed and their baseline
   responses recorded, then re-checked on the patched build; a changed response = broken behaviour =
   rejected. The regression set is *not* written or invented by the model (research shows APR agents
   mis-identify regression tests; deriving it from real traffic sidesteps that). This is the executable
   **regression proof**.
3. **Static re-scan** (`src/autonomy/rescan_gate.py`) — the taint scanner is re-run on the patched file; if a
   finding of the same **class** still lands there, the fix was input-level, not class-level → rejected, with
   the still-present data-flow as the counterexample. Prevents an LLM "fix" that stops one payload and leaves
   the sink reachable.
4. **Sibling-sink review** (post-acceptance) — the same class is re-scanned across the tree; any twin call
   site the patch did not cover is surfaced as a candidate (bypass review), so the fix's scope is honest.

For template fixes, re-verification is a re-scan (the weak literal must be gone) — a literal swap always
compiles, so it needs no build gate. Java LLM fixes rebuild `--offline` (incremental, no network on an
offline host).

## 4. The audit trail (6 artifacts per run)

Written to the `--out` directory, these make an entire run reproducible and reviewable:

| artifact | proves |
|---|---|
| `<out>.csv` | the claimed vulnerabilities (confirmed only) with reproducible evidence |
| `<out>.json` | all findings incl. candidates (full records) |
| `coverage.json` | the evidenced coverage ledger (§5) |
| `exchanges.jsonl` | every confirmed finding's actual attack request (numbered, citeable) |
| `llm_trace.jsonl` | every LLM query + response + model + timing |
| `run.json` | manifest: target, timestamp, counts by class/severity, coverage, artifact index |

This satisfies "all agent runs, fuzzing logs, LLM query traces, and patch-generation logs must be available
for audit."

## 5. Coverage ledger — verifying the negative space

"Zero findings is never 'clean'." Every (route, class) the run examined is recorded
(`src/autonomy/coverage_ledger.py`) with one of **5** outcomes — `reported`, `no_issue_found`, `ruled_out`,
`not_applicable`, `needs_follow_up` — and the last **3** require evidence (the control named, why it's N/A, or
the gap: missing creds / unconfirmed reachability). So "we didn't report X" is itself a checkable, evidenced
statement, not silence. Example (NodeGoat run): 33 `no_issue_found` + 198 `needs_follow_up` over the examined
surface.

## 6. Honestly not yet verified

- **Authenticated confirmation** depends on a supplied `--auth` spec (proven on DVWA); an unseeded target
  yields only unauthenticated/config confirmations.
- The **LLM repair gate** is exercised in tests and the mechanism is wired across 3 backends; a full
  end-to-end LLM patch on a live seeded app is the remaining demonstration.
- **Request-smuggling** stays candidate-tier (timing is not a clean proof), so it is never in the verified set.

See `docs/ARCHITECTURE.md` (pipeline), `docs/DETECTION.md` (FIND), `docs/PROVE.md` (confirm), `docs/PATCH.md` (fix).
