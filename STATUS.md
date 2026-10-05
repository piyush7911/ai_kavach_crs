# Where we are (2026-10-06)

First finale target: **OWASP NodeGoat** (Node.js, Express, MongoDB). Rules: own hardware, declared models
only, no unauthorised network (so **no npm registry**), real fixes that keep the app working. Local model:
`gemma4:12b`. Plan: [`NODEGOAT_PLAN.md`](NODEGOAT_PLAN.md). Track 1/2 interface:
[`benchmarks/nodegoat/CONTRACT.md`](benchmarks/nodegoat/CONTRACT.md).

## What exists

| Area | State |
|---|---|
| C pipeline (autonomous mode, adaptive repair, sandbox, hardening) | done; cJSON `cJSON_Minify` found and patched with no hand-written proof |
| **Track 1** (runner, manifest, 12 PoVs + variants, 12 regression flows, loopback sandbox, scoring) | done by the other half; needs MongoDB 4.4 |
| **Track 2** detection: 233 vendored Semgrep rules + 7 generic Node rules + generic flow analysis | done, unit-tested; held-out DVNA: 6 of 6 core injection classes with the local model |
| Dependency audit | **offline**: lockfile vs a vendored advisory snapshot (400 KB, 7,216 advisories); same 10 packages as `npm audit` on NodeGoat |
| Track 2 repair: patch splicing + policy gate, probes + variants, repair loop, **`fix` command** | written and unit-tested with a stub runner (121 passed, 2 marked known gaps); **never run against a live app** |
| Audit trace + endpoint pinning | every model call logged to `KAVACH_LLM_TRACE`; `KAVACH_ALLOWED_ENDPOINTS` / `KAVACH_ALLOWED_MODELS` enforced |

## The new command (Track 2)

    python -m src.jsauto.fix --target benchmark_workspace/NodeGoat --runner benchmarks.nodegoat.runner \
        --out reports/js_fix/run1 [--classes open-redirect,eval-injection] [--attempts 3] [--max-findings N]

For each finding: **confirm** the exploit on the unpatched app (if it does not reproduce it is dropped and
the result can never be `proven`), keep only the **variants** that work on the unpatched app, ask the model
for a fix, **vet** it (parse + patch policy), run the **start / replay / regress / hardening** gates, and
feed every rejection back. Patches accumulate on a copy (`combined/`), so a later fix sees earlier ones.
At the end the final tree is started, the flows are run, and every confirmed exploit is replayed.
Outputs: `evidence.json`, `patches/<id>.diff`, `final.diff`, `combined/`.

## What the friend needs to do (live test on the laptop that has MongoDB)

Nothing below has been run live; expect some first-run fixes, and please report them rather than work
around them.

**0. Setup**
1. `git pull origin pre-finale`. Python env with the project packages (`pip install tree-sitter-javascript`
   if missing; see `INSTALLED.md`). Ollama running with `gemma4:12b` pulled. MongoDB 4.4 on
   `127.0.0.1:27017`. NodeGoat with `node_modules`: `sh benchmarks/nodegoat/setup.sh`.
2. Environment (from `ai_kavach_crs/`):

        export OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=ollama
        export MODEL_ALPHA=gemma4:12b MODEL_BETA=gemma4:12b MODEL_GAMMA=gemma4:12b
        export KAVACH_RUNNER_MODULE=benchmarks.nodegoat.runner
        export KAVACH_ALLOWED_ENDPOINTS=localhost:11434 KAVACH_ALLOWED_MODELS=gemma4:12b
        export KAVACH_LLM_TRACE=reports/js_fix/trace.jsonl

**1. Unit tests, new files only (no app needed)**

    python -m pytest tests/unit/test_jsauto_fix.py tests/unit/test_jsauto_repair.py \
        tests/unit/test_jsauto_repair_loop.py tests/unit/test_llm_audit.py \
        tests/unit/test_jsauto_more.py tests/unit/test_jsauto_offline_deps.py -q

Expected: 121 passed, 2 xfailed. Anything else: send the output.

**2. Check the runner on the untouched tree** (your own commands): `start`, `regress` three times in a row
(must pass every time: a flaky flow makes every patch look like a regression), and `replay` the existing PoVs.

**3. Smoke test one class, then widen**

    python -m src.jsauto.fix --target benchmark_workspace/NodeGoat --out reports/js_fix/open_redirect \
        --classes open-redirect --attempts 3

Then `eval-injection`, `ssrf`, `reflected-output`, then everything (no `--classes`).

**4. What to look at and send back**
- `evidence.json`: `by_status`, and per finding `confirmed`, `variants` (kept of total), `status`, `reason`,
  `attempts[].stage`.
- `final.diff` (is each patch a real fix?) and `final_check` (start, regression, exploits blocked vs still working).
- `trace.jsonl` line count (one line per model call) and the seconds per finding.

**5. Things I expect to go wrong, and what each would mean**
- **`confirmed: false` for a class the PoVs already cover.** The engine builds its own exploit from the
  route and the fields the handler reads, so its request can differ from yours. `evidence.json` now keeps the
  generated `exploit` and `control`; send them with the runner's detail text. The likely fix is in
  `config/js_probes.json`.
- **`login failed` from `replay`.** The engine uses `login_as: "user"`; tell me if the route needs admin.
- **A patch fails at `regression` every time.** First rule out a flaky flow (step 2).
- **Everything `unresolved` at the `apply` stage.** The model's answer did not parse; check the trace to see
  what gemma returned (it may be wrapping code in prose or returning a diff).
- **SSRF probe never calls back.** The probe uses the runner's `{OOB_URL}` / `{OOB_MARKER}` placeholders
  and the `oob_marker` oracle; confirm `replay` fills them in inside a query string.

**6. Remaining Track 1 items**
- `node_modules` must be present at the venue: `npm install` needs the registry, which is not allowed.
- Answer for the organisers: confirm the venue has no registry access (we assumed none).
- Re-run `score` on the engine's new findings file once step 3 has produced one.

## First live run (friend's laptop, 2026-10-06) and what it changed

Report: `reports/js_fix/LIVE_RUN_REPORT.md`. Runner, flows and PoVs worked on the untouched tree; the model
was `gemma4:e2b` over the LAN (not the 12b), far weaker than intended.

- **open-redirect: unresolved, gates behaved.** Confirmed, 4/4 variants kept; attempt 1 was rejected by
  **hardening** (blocked the main payload, leaked the protocol-relative variant), attempt 2 did not parse,
  attempt 3 still exploitable. No fake fix was reported.
- **eval-injection: a correct fix, reported only `patched_unproven`.** Two engine bugs, both fixed:
  1. my marker `31337+1` is rejected by the app's "total at most 30" check, so the result is never shown
     -> the marker is now `7*3` (matched as a standalone `21`);
  2. the request sent only `preTax`, but the handler `eval`s `afterTax` and `roth` too (undefined -> "Invalid")
     -> the flow analysis now records every request field the handler reads, and the probe sends all of
     them (benign value for all but the carrier).
- **Also found while checking against the real app:** the SSRF finding produced no probe, because the sink
  argument is a variable (`url`). The flow analysis now tracks which request fields feed each sink
  (including `const { x } = req.query` and values passed into other files), and probes use them.
- **New safeguard:** at confirmation a benign *control* request is sent with the same oracle; if the oracle
  also matches it, the exploit is not trusted (`control_matched` in the evidence). The exploit and control
  are now kept in `evidence.json`.

Engine now generates, for NodeGoat: eval `POST /contributions {preTax: 7*3, afterTax: 1, roth: 1}` (same shape
as the confirmed PoV), SSRF `GET /research?url={OOB_URL}&symbol=1`, open-redirect `GET /learn?url=...`.
Unit tests for these: 102 passed, 2 known gaps (xfail). Not yet re-run live.

**Friend, next:** `git pull`, re-run step 3 for `eval-injection`, `ssrf`, `open-redirect`, then everything,
ideally with the `gemma4:12b` model (check `ollama list`; keep `KAVACH_ALLOWED_ENDPOINTS` equal to the host
you really use). Send `evidence.json` again; each finding now carries its `exploit`, `control`, `confirmed`.

## Measured

- **NodeGoat static detection: 12 of 12 answer-key bugs (recall 1.0), precision 0.92.** The one "extra" is a
  real bug outside the key: `/benefits` lets any logged-in user update anyone's benefits (the commented-out
  `isAdmin` fix shows it), reported as an IDOR. The key should probably gain an entry for it.
  The last three classes came from new GENERAL rules, not a list: (1) **XSS**: a request-derived value passed
  to `render()` that the template prints raw, or at the start of a URL attribute, in an event handler or in a
  script block, found by a small template analyser (mustache/handlebars/swig/nunjucks, ejs, pug syntaxes,
  HTML-context aware); (2) **IDOR**: a client-supplied identifier used as a data-lookup key with no comparison
  to the authenticated identity and no role middleware on the route; (3) **CSRF**: cookie sessions + a
  state-changing route + no active CSRF protection, anchored on a disabled `csrf()` call if there is one.
  Evidence for generality: all three are still found after renaming every parameter, file and function, and on
  the unseen DVNA app the same rules find its real XSS, its real IDOR (`userEditSubmit`) and its missing CSRF
  (plus two low-confidence IDOR guesses on a shared product table, which are probably false positives).
  **Detected is not confirmed or fixed:** XSS has a live probe (javascript: URL, replayed with variants) that has
  not been run yet; IDOR and CSRF have no probe oracle in the replay contract, so they can only be patched
  without a PoV gate.
- DVNA (unseen, untuned): without a model 5 of 6 core injection classes found by some detector, 3 of 6 by flow
  alone; **with the local model classifying unknown calls, 6 of 6** (6 model calls, 84 s; one run).
- Local model: with thinking on, one short request took 118 s and returned nothing; off, 9.3 s.

### Live end-to-end on NodeGoat (2026-10-06) — the loop is closed

Run on a real MongoDB 4.4 + the Track-1 runner, model `codegemma:7b` over LAN (no cloud). The
`fix` command ran detect -> confirm -> local-model patch -> policy -> PoV -> regression -> hardening:

- **4 of 5 confirmable bugs PROVEN + HARDENED: eval, NoSQL, SSRF, XSS.** Only open-redirect is
  unresolved (every model fails it; it is the deterministic-template candidate). proven went 2 -> 4
  after Track 1 wired the NoSQL boolean-differential oracle and XSS probes landed.
- **Overfitting check:** NodeGoat ships each fix as a comment (e.g. `// const preTax = parseInt(...)`).
  With EVERY comment stripped from the source (41 files, all still parse), all 4 stay proven. The model
  reasons the fix, it does not copy the answer key — so the result is expected to transfer to the jury's
  customised app (which has no such comments).
- Repairer bake-off (same bugs, same gates): `codegemma:7b` 4 proven; `gemma4:e2b` 1; cloud
  `gpt-4.1-mini` 1 (different bug). A 7B *code* model beat a frontier cloud *chat* model — the bottleneck
  was clean code output, not intelligence. `codegemma:7b` is the finalist local model (non-Chinese, fits).
- NoSQL/SQL now have a real proof gate (differential oracle); IDOR has the runner's two-user `idor`
  oracle and CSRF the tokenless-POST status oracle — wiring those two probe classes is the remaining
  confirm work. Classes with no oracle are patched WITHOUT a PoV gate and never reported `proven`.

Fresh checkout now `pytest`s clean: `tree-sitter-javascript` pinned, and the C-side tests skip when
clang cannot build+link (broken/absent SDK) or no API key is set, instead of failing red.

## Not done / not measured

- **Nothing has run against a live app**: no MongoDB on this Mac. Probes, confirm, repair gates and the final
  check are tested with stubs only.
- No probe oracle for SQL/NoSQL injection, ReDoS or deserialization (listed, with reasons, in
  `config/js_probes.json`); those can only be repaired without a PoV gate and are never reported `proven`.
- Gemma's quality as a *repairer* on real handlers is unmeasured; only its classification has been measured.
- Two known detector gaps are marked `xfail`: aliased destructured imports and chained `router.route()`.
