# NodeGoat benchmark — two independent tracks

**Target:** https://github.com/OWASP/NodeGoat (public; commit `c5cb68a`, 2023-06-21). Node.js +
Express + MongoDB, ~3,000 lines of JS, intentionally vulnerable (OWASP Top 10).
**Scope rule:** the old C suites stay untouched and are not run for this effort. NodeGoat is the
benchmark. The jury's final app may be a *customized* version, so the engine must work on code
it has not seen: **nothing in the engine may read `manifest.json` or hard-code a NodeGoat path.**
The manifest is for scoring only.

## What the rules reward (jury, 4 parameters)

| Parameter | Our measurable |
|---|---|
| Autonomous bug discovery: precision and efficiency | recall and precision against the manifest; time to first true finding |
| Automated patch generation: quality, correctness, speed | patches that pass PoV + regression + variants; seconds and model calls per fix |
| Regression proof | the regression flow suite passes on every accepted patch |
| Scalability and architecture: lightweight, novel, adaptable | footprint, model calls, how little changes for a new app |

Rule constraints that shape the design: rate-limited probing only (no unthrottled fuzzing);
touch only our own instance; patches must be real fixes (no auth bypass, no disabling checks);
full prompt/response log for audit; only declared model endpoints.

## The contract between the tracks (agree first, 30 minutes, then split)

**1. `benchmarks/nodegoat/manifest.json` (Track 1 writes, scoring only):**
`{ "commit", "vulns": [ { "id": "NG-01", "owasp": "A1", "cwe": "CWE-95", "class": "eval-injection",
"kind": "code|dependency|config|secret", "file", "line", "pov": "povs/ng01.json",
"variants": ["povs/ng01_v1.json"] } ], "flows": ["login", "profile", ...] }`

**2. Exploit request (language-neutral, produced by Track 2's probes and by Track 1's PoVs):**
`{ "method", "path", "headers", "body", "login_as": "user|admin|none", "success_if": {"status", "body_regex", "oob_marker"} }`

**3. Runner CLI (Track 1 implements, Track 2 calls):**
```
python -m benchmarks.nodegoat.runner start   --tree DIR --json out.json     # seed DB, start on a free port, health check
python -m benchmarks.nodegoat.runner replay  --tree DIR --exploit E.json    # exit 0 = NOT exploitable, 1 = exploitable
python -m benchmarks.nodegoat.runner regress --tree DIR                      # exit 0 = every flow matches the golden
python -m benchmarks.nodegoat.runner score   --findings F.json --patches P  # manifest-based scoring (benchmark only)
```
Each call starts the given tree on its own port and its own DB name, throttled, and stops it.
These map directly onto the DRV loop's existing `build_command` / `pov_command` / `test_command`
templates, so the repair loop needs almost no change.

**4. Finding (Track 2 emits):** `{ "id", "source": "semgrep|npm-audit|probe", "class", "file", "line",
"evidence", "exploit": <exploit request or null>, "confidence" }`

Both tracks code against stubs of the other until it lands.

---

## Track 1 — Target and verification ("ground truth"; no LLM needed)

Goal: NodeGoat runs reproducibly on this Mac, and any patched tree can be judged in seconds.

| # | Task | Done when |
|---|---|---|
| 1.1 | **Runtime spike (risk first).** NodeGoat uses `mongodb` driver 2.x, which MongoDB 5.1+ rejects (legacy opcodes removed); the repo's compose file pins `mongo:4.4`. This Mac has Node 25, no Docker, no MongoDB. Pick one and prove it: Colima + `mongo:4.4`, or Homebrew Mongo 4.4 under Rosetta. Pin Node 14. | `npm start` serves `/login` and `db-reset.js` seeds, from one command |
| 1.2 | **Sandbox for a web app.** Our sandbox denies all network; the app needs loopback (its port and Mongo). Add a loopback-only mode, still denying everything external. Test with a positive control. | app runs sandboxed; outbound connect refused |
| 1.3 | **Manifest.** Read the code and tutorial pages; list every real defect (eval in contributions, `$where` in allocations, SSRF in research, open redirect in `/learn`, weak sessions, hard-coded secrets, committed private key, vulnerable dependencies, XSS, ReDoS, ...) with file:line, class, kind. | `manifest.json` reviewed by a second person |
| 1.4 | **PoVs and variants**, one per vuln, each pre-flighted both ways: succeeds on the vulnerable tree, fails on a known-fixed tree. Variants are encoded or alternative forms of the same attack (for example SSRF host spellings), the web analogue of re-fuzzing. | each PoV has a measured true/false pair |
| 1.5 | **Regression flows** replacing Cypress: login, signup, profile update, contributions, allocations, memos, research, benefits, logout. Golden responses recorded from the untouched app; compare status, redirects and normalised bodies. | passes 3 runs in a row on the original (no flakiness) |
| 1.6 | **Runner CLI** per the contract above, with port/DB isolation, request throttling, timeouts that kill hung servers (the lesson from the C work), and orphan cleanup. | all four commands work; `start` in under 10 s |
| 1.7 | **Scoreboard** (`score`): recall, precision, time to first find, patch correctness, seconds and model calls per fix, cost. | one JSON per run, every number traceable |

Track 1 also owns: `INSTALLED.md` entries for anything installed.

## Track 2 — Detect and repair for JavaScript ("the engine")

Goal: given only a path to an unknown Node app, find real bugs, patch them, and show evidence.

| # | Task | Done when |
|---|---|---|
| 2.1 | **Language-neutral core.** `Finding` and exploit types; make ingest, census and the runner not assume C; keep the C pipeline working. | existing 253 unit tests still pass |
| 2.2 | **Static detection.** Semgrep JS/Node rules, `npm audit` (or an offline advisory check) for vulnerable dependencies, a secrets scan. Map each hit to its enclosing function with `tree-sitter-javascript`. | findings emitted on NodeGoat without reading the manifest |
| 2.3 | **Dynamic probes (rate-limited).** Crawl the running app from the routes it exposes; send a small, fixed battery (injection markers, SSRF to our own listener, redirect targets, auth-less access to protected routes). Emit `exploit` requests. Hard caps on requests per second and total. | confirmed findings carry a replayable exploit |
| 2.4 | **JS context and prompts.** Extract the handler, its DAO and imports; Node-specific system prompts; allow edits to `package.json` (dependency bumps) and config, which the rules permit as "configuration fixes". | patch applies to a JS file or `package.json` |
| 2.5 | **Policy gate for JS.** Same philosophy as C: no editing tests, no disabling auth/CSRF/validation, no catch-all `try/catch` that swallows the bug, no logic bombs; bounded size. Dependency bumps allowed only inside declared semver range or with a recorded reason. | red-team set of JS cheats caught |
| 2.6 | **Repair loop on the runner.** Wire the adaptive strategy (alpha, beta, gamma on a probed stronger model) to `runner replay` and `runner regress` as the PoV and regression gates. | a real finding goes finding -> patch -> gates |
| 2.7 | **JS hardening.** After gates pass, replay the exploit variants and re-run regression; falsified patches go back to the model once with the reason. | variant battery runs per accepted patch |
| 2.8 | **Audit and compliance.** Log every LLM prompt and response to the run directory; pin model endpoints to the declared list (no silent escalation to an undeclared model); cap CPU and request rate. | `llm_trace.jsonl` per run; endpoint list enforced and tested |

## Order and checkpoints

1. **Together:** freeze the contract above (30 min).
2. **Parallel:** Track 1 does 1.1 first, since it is the largest unknown; Track 2 starts with 2.1 and 2.2, which need no running app.
3. **Integrate:** Track 2's 2.6 runs against Track 1's runner. First end-to-end run on one vulnerability (suggest `/learn` open redirect or the `eval`).
4. **Then:** widen to all manifest entries; measure; tune only on a held-out subset of vulnerabilities, and report the rest as untuned.

## Risks to settle early

- **MongoDB on Apple Silicon without Docker** (1.1) can eat hours; decide within the first hour.
- **Overfitting to the public repo.** The jury app is customized. Keep a held-out set of manifest entries that no prompt or rule is tuned on.
- **Dependency vulnerabilities are a different kind of fix** (bump a version, then run regression) and scoring needs to count them separately from code fixes.
- **Some NodeGoat code already carries "fixed" comments** (for example the allocations IDOR). The manifest must record what is actually vulnerable at this commit, verified by exploit, not by comments.
- **Declared model endpoints:** needs an answer before 2.8 can pin them.

---

## Track 2 status (updated 2026-10-05)

| Task | State | Evidence |
|---|---|---|
| Local model | **done** | `qwen3:8b` (5.2 GB). Thinking must be off: default thinking spent 800 tokens and 54 s and returned an empty answer; `reasoning_effort=none` answered in 1.7 s. On a real NodeGoat handler (`eval`), none fixed it in 15 s; `low` used all 1,500 tokens in 89 s and returned nothing. `llm_client._reasoning_kwargs`, `KAVACH_REASONING`. |
| 2.2 static detection | **done** | `python -m src.jsauto --target DIR`. 233 vendored Semgrep rules (offline) + 7 generic Kavach rules (`config/semgrep/kavach_js.yaml`) checked against an annotated fixture (positives and negatives). On NodeGoat: 11 code/config findings + 10 runtime-dependency findings in about 5 s, each mapped to its enclosing function; 3 hits suppressed with a recorded reason. |
| Dependency audit | **done, needs network** | `npm audit --omit=dev` (runtime only: 51 advisories vs 145 with dev tooling). Fails loudly, never returns an empty "clean" list. **Decision needed: is querying the npm registry allowed at the event?** If not, we need a vendored advisory snapshot. |
| 2.1 neutral core | partial | `Finding` type and a separate `src/jsauto/` package; the C pipeline is untouched (266 unit tests pass). |
| 2.3 dynamic probes | not started | needs Track 1's runner to run the app |
| 2.4 JS context and prompts | not started | |
| 2.5 policy gate for JS | not started | |
| 2.6 repair loop on the runner | not started | needs Track 1 |
| 2.7 JS hardening | not started | |
| 2.8 audit and endpoint pinning | not started | |

Known weaknesses of the detector, stated plainly:

- Static hits are **candidates**. The `$where` rule is syntactic: it flags the vulnerable interpolation but would also flag a safe one (numerically parsed) if both were live code; only a dynamic probe confirms.
- Not detected statically: XSS through `marked`/templates, insecure direct object references, weak session/crypto design, missing CSRF. Probes (2.3) and model review have to cover these.
- Semgrep skips `test/` directories by its own default; findings in test code are never reported.
