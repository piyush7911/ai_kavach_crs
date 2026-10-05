# AI Kavach — Pre-Finale Build Plan

Goal: arrive at the venue with the best solution we can build, with every claim measured.
This plan covers **only the work before we travel**. How we use the 36 hours is decided later,
once the rules are known.

Status key: **DONE** · **IN PROGRESS** · **TODO**. Evidence tags: **[code]** we read the
implementation, **[measured]** we ran it on this machine.

---

## 0. TL;DR

1. **The engine is strong but the product path is not wired.** `src/main.py` (what runs when
   someone points the tool at a new repo) is Semgrep → patch only **[code]**. It does not call
   the fuzzer, crash triage, hardening or CBMC. Those run only inside `benchmark.py`, against
   harnesses we wrote by hand for our own targets. On an unfamiliar repo the proof-of-
   vulnerability gate would be **skipped**, which our own rule says we never count as a pass.
   **This is the single biggest risk, so it is workstream A and it comes first.**
2. **"Where does inference run?" is the first question a defence audience asks.** Our
   published results are on a cloud model. The local path exists but is unmeasured.
   Workstream B measures it.
3. **Our real-CVE evidence is one small library** (cJSON, 3 defects). Workstream C widens it
   to larger, better-known libraries.
4. **We should be able to show, not just say.** A small FastAPI dashboard lets anyone watch a
   live run, start a benchmark, and **drag and drop a new repo**. Workstream D.
5. **Our real novelty is the verifier, not the patcher.** Bounded model checking of the
   actual patched code, behavioural contracts for what a fix may change, and a verifier we
   test against deliberate cheaters. Workstreams E and F sharpen exactly that.
6. **Discipline:** build in the order of §6, validate on a held-out set we do not tune on,
   one full sweep at the end, every number traceable to one run directory.

---

## 1. Where we stand (measured)

Run 2026-08-30 (`reports/benchmark_runs/20260830_094305/` plus the standalone reports):

| | |
|---|---|
| Targets patched (all gates) | **44 / 44**, 95% CI [92.0, 100.0] |
| PoV-proven (exploit replayed on the rebuilt patched binary) | **30 / 30** |
| Hardening | 32 attacked, 0 falsified, 5 not attacked (no applicable check) |
| Real published defects (unmodified cJSON) | 3 / 3 patched, PoV-proven, hardened |
| Cost / time | **$0.0739** total · 804 s · median 5.8 s and $0.0009 per target |
| Footprint | 1,300 MB peak RSS · no GPU · 0 ML frameworks · 0 bytes of model weights |
| Provenance | 33 of 44 targets are our own code; 11 use third-party code |
| Tests | 125 unit tests, no API calls |

What is distinctive and defensible:

- **Bounded model checking (CBMC) on the actual patched C code.** 3 proofs today, all on
  synthetic targets.
- **Behavioural contracts** (`preserve`, `restrict`, `replace`) that state what a fix is
  allowed to change, so a correct patch is not falsified for the wrong reason.
- **Pre-flighted proofs of vulnerability:** compiled against the unpatched build first, so a
  patch can never be credited for fixing something never shown broken.
- **A verifier we test against deliberate cheaters** (the cheat detector).
- **Honest accounting:** `SKIPPED` is never a pass; hardening refuses to credit a check that
  compared nothing; the harness rejects mismatched units in its own rollup.

---

## 2. Gaps, ranked by finale risk

| # | Gap | Evidence | Risk |
|---|---|---|---|
| G1 | **No autonomous path for unseen code** | `src/main.py` is Semgrep-only; fuzz harnesses are hand-written per target | **Critical** |
| G2 | **Local-model results unmeasured** | Cloud-only numbers; local path never run end to end | High |
| G3 | **Real-CVE corpus is one small library** | 3 cJSON targets, short functions | High |
| G4 | **Nothing runs live for a viewer** | CLI and a deck; the earlier UI was a labelled mock and has been removed | High |
| G5 | **No reproducibility bundle** | No manifest, tool versions, or replay script per run | Medium |
| G6 | **Untrusted code runs on the host** | Patches and uploaded repos are compiled and executed natively; no sandbox, no patch policy, no scrub of prompt-injection in source comments | Medium-High |
| G7 | **Verifier red-teamed on only 2 cheat classes** | Cheat detector covers 2 | Medium |
| G8 | **No detection precision/recall** | Listed as a known gap in our docs | Medium |
| G9 | **No formal proof on a real CVE** | 3 synthetic proofs only | Medium |
| G10 | **No defence-domain framing** | Corpus and docs are generic | Medium |

A cheat we tried and could **not** make work **[measured]**: adding
`__attribute__((no_sanitize("address","undefined")))` to the vulnerable function on SYN-06.
ASan still fired, because the unprotected store is followed by an intercepted `printf`/`free`.
So that is not a demonstrated hole, but it shows which cheat classes are untested.

---

## 3. Positioning (what we say, and what must back it)

> **AI Kavach doesn't only patch. It proves the patch holds, tries to break it, and reports
> exactly what was and was not shown, on a laptop, for about seven cents.**

| Scoring axis | Claim | Must be backed by |
|---|---|---|
| **Novelty** | The verifier is itself tested against cheaters; CBMC runs on the real patched code; behavioural contracts decide what a fix may change | Cheat suite with a detection rate (E); one CBMC result on a real CVE fix (G); contract table |
| **Lightweight** | $0.07, 1.3 GB, no GPU, no services: one `pip install` plus clang | Already measured; add a **local-model run** so "no GPU" does not quietly mean "cloud" (B) |
| **Resource utilisation** | Cost, time and memory per target; deterministic tools do the work, the LLM only proposes | Already measured; add per-stage breakdown (D) |

Lead with: **"we test the tester"** and **"a proof about the program."** Do not lead with
"we attack our own patches" as if it were unique to us.

---

## 4. Hardware reality: MacBook Air M3, 16 GB

Measured from the Ollama server log on this machine **[measured]**:

- **Usable GPU memory is 11.8 GiB**, not 16. macOS caps the GPU working set at about 75% of RAM.
- Default context is 4,096 tokens. Our Critic prompt can exceed that (up to ~4,000 chars of patch
  plus ~4,000 of gate output plus the vulnerability context), so `num_ctx` must be raised (8,192).
- The Air is fanless: sustained generation will throttle. Plan demos around short bursts and
  avoid back-to-back full sweeps on battery.

Model options (sizes read from the Ollama registry **[measured]**):

| Model | Size | Verdict on this machine |
|---|---:|---|
| `qwen3-coder:30b` | 19 GB | Does **not** fit (weights alone exceed the 11.8 GiB budget) |
| `qwen3-coder-next` | 52 GB | No |
| `deepseek-coder-v2:16b` (MoE) | 8.9 GB | Fits; fast per token; weaker on C repair, to be tested if needed |
| `qwen2.5-coder:14b` | 9.0 GB | Fits but tight next to clang and the fuzzer; slow on a fanless chip |
| **`qwen2.5-coder:7b`** | **4.7 GB** | **Chosen.** Comfortable; leaves room for the harness |

**Decision: `qwen2.5-coder:7b` first** (IN PROGRESS: downloading). Test the 14B only if the 7B
result shows quality, not speed, is the bottleneck. Decide with data, not preference.

**Local model measured on this machine [measured]** (`kavach-coder:7b`, a derived
`qwen2.5-coder:7b` with `num_ctx 8192`, `temperature 0`, `seed 1337`; definition in
`config/ollama/Modelfile`):

| Measurement | Value |
|---|---|
| Throughput, steady state (warm-up excluded) | **15.2 tok/s** |
| Repair-shaped request (477 in / 134 out) | 8.8 s |
| Critic strict JSON-schema call | **works**, 7.4 s, all required keys returned |
| Memory held by the loaded model (Ollama's own report) | **4,882 MB**, 100% GPU, 8,192 context |
| Our client against Ollama | **works unchanged** through `OPENAI_BASE_URL` |

Two measurement traps found along the way: (1) the first request includes model load and
reads as ~11 tok/s, so a warm-up must be excluded; (2) **`ps` RSS showed 24 MB for a model
Ollama reports as 4.77 GiB**, because Apple-Silicon weights live in GPU-visible memory. Local
footprint must be asked of Ollama, never read from RSS. A local run's real memory is the
harness plus ~4.9 GB, not the harness alone.

Workload to serve (mean per call, from the last run **[measured]**): ~1,520 input tokens,
~287 output tokens. A full 44-target sweep is ~161 calls, about 46k output tokens. Expect that
to be tens of minutes of generation locally, not 13: **measure it, then publish it.**

---

## 5. Workstreams

Priority: **P0** must ship before we travel, **P1** should, **P2** only if ahead. Every item has
an acceptance test that produces a number.

### A. Autonomous mode for unseen code — P0 — TODO

Goal: `python -m src.main --target <repo> --mode auto` runs ingest → scan → harness → fuzz →
triage → patch → verify → harden → evidence, with no hand-written harness or PoV.

**Design principles (ours, derived from what went wrong on our own targets):**

1. **Finding-driven, not API-driven.** The pipeline already knows *which function* is suspect
   (Semgrep location or crash frame). Tree-sitter finds that function's callers. The harness
   reaches the function through a real call path.
2. **Preconditions are mined from real callers.** Three of our own targets (SYN-03, SYN-12,
   SYN-16) were unfixable by contract because the harness violated a precondition real callers
   never violate. So the builder reads how real callers allocate and bound their arguments
   and mirrors that. Buffers are allocated at exactly the size claimed.
3. **Success means "reaches the flagged function", not "gained some coverage".**
4. **Deterministic first, model second.** Common shapes (`(buf, len)`, `(C string)`,
   `(struct *, buf, len)`) get a template harness with no model. The LLM drafts only for shapes
   the templates cannot express, and the compiler and the reach check judge its output.
5. **It plugs into the existing pre-flight.** The crash becomes the PoV and is validated
   against the unpatched build. If no fair harness can be built the result is **"unproven: no
   PoV, reason: …"**, never a silent skip.

| Step | What | Done when |
|---|---|---|
| A1 | `src/autonomy/`: `ingest` (snapshot + file census + build detection), `events` (JSONL stage stream), `runner` (stage orchestration reusing `fuzz_pipeline`, `crash_triage`, `orchestrator`, `hardening`) | Run on a repo with no hand-written harness and see the PoV gate **PASS**, not skipped |
| A2 | `harness`: caller-derived preconditions, template library, LLM fallback, reach judge, fairness check | Builder reaches the flagged function on ≥ 2 of 3 held-out libraries |
| A3 | Build detection: flat `.c` set, Makefile, CMake; otherwise require `--build-cmd` and say so | An unknown build system fails loudly with a message |
| A4 | Tests, including: a harness that compiles but returns early is **rejected**; a harness that violates a caller precondition is **rejected** | 0 skipped gates in auto mode on held-out targets |

Prior art: LLM-assisted fuzz-harness generation is established public practice (for example
Google's OSS-Fuzz-Gen). Our design is built from our own pipeline and the lessons above, and
the design note should say so.

### B. Measured local-model run — P0 — IN PROGRESS (readiness measured; benchmark run pending)

- Pull `qwen2.5-coder:7b` (**in progress**).
- Make the client work against Ollama: `response_format` JSON schema for the Critic, `seed`,
  `num_ctx`, `max_tokens`; fail with a clear message if the server lacks structured output.
- Run the **3 real CVEs + a 10-target synthetic subset** locally. Record pass rate, time per
  target, tokens/s, peak RSS, cost ($0), and the same on the cloud model.
- **Publish whatever comes out.** A 7B model failing some targets is acceptable: the gates turn
  a weaker model into a lower pass rate, not into unsafe patches. That is precisely the claim,
  and a measured weak result is more credible than a claimed strong one.
- Replace every estimate in our docs about local GPU sizing and speed with the measurement.

### C. Wider real-CVE evidence — P0 — TODO

Add to `tests/real_cve_suite/`, each **validated in both directions** (PoV reproduces on the
vulnerable commit and stops on the upstream fix), using upstream git worktrees:

- **zlib CVE-2022-37434** (`inflate`, gzip header extra field; affects callers of
  `inflateGetHeader`; vulnerable in 1.2.12). Needs a small driver that calls `inflateGetHeader`.
- **libpng**: one published CVE in a function with a flat-ish build (needs the prebuilt
  `pnglibconf.h`). **Verify the CVE ID and its fix commit against upstream before naming it
  anywhere.**
- One embedded/protocol-parser CVE if a buildable one exists (see H).

Success is not PASS alone: **accepted patch, PoV-proven, hardened, and a CBMC result if G lands.**
Budget 3–4 h each; cut libpng if zlib takes more than 5 h.

### D. FastAPI live dashboard — P0 — DONE except drop-and-analyse (needs A)

One static page served by FastAPI. No node, no build step, no database. Anyone can watch it.

**Panels**

1. **Status strip:** tool health (clang, libFuzzer, AFL++, Semgrep, CBMC, Ollama server and
   model), active provider (Cloud / Local), machine (chip, RAM), run state.
2. **Measured results:** the latest run, read from `reports/benchmark_runs/*` only: counts,
   CI, PoV, the three hardening numbers, cost, time, RSS, per-suite and per-target tables with
   gates, drill-down to the patch and verdict. Always labelled with the run id and date.
3. **Run benchmark:** suite checkboxes, flags (harden, formal, memory, fuzz seconds), provider
   (cloud / local model), target filter, Start / Stop, per-target progress, live log.
4. **Special cases:** cheat detector (run + table), verifier red-team suite (F), real-CVE suite
   (setup check + run), pre-flight PoV validation, unit tests (run + count).
5. **Drop a repo:** drag and drop a zip or a folder; shows detected files and a proposed build
   command (editable) and optional PoV and test commands; **Start** runs auto mode (A) with a
   live stage timeline, findings table, patch diff viewer and a downloadable evidence bundle.
6. **Resources:** server process CPU and RSS, tokens and cost so far, model tokens/s.
7. **How it works:** the pipeline, the gate list, and an "what this does not show" box.

**Hard rules for the dashboard**

- **It displays only what a run produced.** No placeholder numbers, no canned events.
  If there is no run, it says so.
- **One run at a time**, with an explicit lock and a visible "busy" state.
- **Safe by default:** binds to `127.0.0.1`; optional token if exposed; upload size limit;
  zip extraction guarded against path traversal; subprocess arguments never built from raw
  user strings; uploaded code is built and run only under the sandbox from F.
- **Event stream is JSONL** (`stage`, `status`, `detail`, `data`) consumed over Server-Sent
  Events. `benchmark.py` gets an `--events` flag so the same panel shows benchmark progress.

**Built (2026-10-01):** `python -m dashboard` serves everything above except the analyse
step. 56 tests cover the upload security rules, job lifecycle, results parsing and the HTTP
layer. Verified live: streaming a real job over SSE, the busy lock returning 409, seven hostile
archives rejected with nothing left on disk, and both zip and dropped-folder uploads. The UI
reuses the design system from `design/ui-concept/` with every mock value removed.

Two defects found and fixed while testing it: the headline defaulted to the newest run (a
1-target spot check) instead of the newest *full* run; and a finished job briefly reported
"starting". Both now have tests.

Acceptance: from a cold start, a person can open the page, see tool health, run the cheat
detector and watch it finish, start a 3-target benchmark and watch it live, and drop a repo
and get either a verified patch or an honest "unproven: reason".

### E. Verifier red-team and patch policy — P0 — TODO

Turn the cheat detector into a **measured benchmark of the verifier**: N cheat patches, a
detection rate, and the layer that caught each. Today 2 classes; target ≥ 10:

1. special-case the replayed PoV input *(have)*
2. gut the function with an early `return` *(have)*
3. remove the feature but keep exit 0
4. disable instrumentation (`no_sanitize` attribute or pragma) *(tried once; did not evade on
   SYN-06; test on a target where the overflow is write-only)*
5. blanket size/NULL guard that rejects all large inputs (breaks benign behaviour)
6. install a `SIGSEGV`/`SIGABRT` handler that exits 0
7. edit the regression test or the build script instead of the code
8. `exit(0)` before the faulting statement
9. environment-conditional bypass (`if (getenv("CI")) return;`)
10. a plausible fix that moves the overflow elsewhere

Add a **patch policy gate**: single file, edit inside the flagged function's span, changed-line
cap, no edits to tests or build files, deny `signal`/`sigaction`/`no_sanitize`/inline asm.
Report the policy as a gate and test each rule.

Publish: "N classes, K caught (by which layer), M slipped, and what we changed." If something
slips, **fix it and say so**; that is a stronger story than a clean sheet.

### F. Sandbox and prompt-injection scrub — P1 — TODO

- Build, PoV and regression run under `sandbox-exec` on macOS (present here) or `bwrap` on
  Linux: no network, writes limited to the workspace. Docker is **not** installed here and must
  not be required.
- Strip and flag known injection patterns in source comments before they reach a prompt; test
  with an injected comment.
- Measure the overhead (we sell "lightweight").
- Word it precisely: say what the sandbox denies and show the test, never "air-gapped" or
  "cannot reach the internet".

### G. Bounded proof on a real CVE fix — P1 — TODO (go/no-go)

Try `cJSON parse_string` (CVE-2019-11834): a proof harness with a bounded input and an explicit
`--unwind`. **2-hour spike.** If CBMC cannot refute the vulnerable function and verify the fixed
one within a stated bound, drop it and keep the 3 synthetic proofs. Do not half-claim it. If it
works, state the bound plainly ("no violation for inputs up to N bytes").

### H. Defence-domain framing — P1 — TODO

One page, not a rewrite: map the weakness classes we handle to defence-relevant software
(protocol parsers, firmware, embedded comms, command-and-control handlers) and add one or two
targets from that world, chosen by **buildability first**, with the CVE verified before it is named.

### I. Detection precision and recall — P1 — TODO

Labelled Juliet subset (good/bad pairs). Run detection; report precision and recall. Guard
against leakage: no tuning on the evaluation split. Report honestly even if low. Our claim is
about repair and proof, not detection.

### J. Reproducibility bundle — P0 — TODO

Per run: `manifest.json` (sha256 of every artefact), `tool-versions.json` (clang, Semgrep, CBMC,
AFL++, Python, model id, seed, system fingerprint), and `reproduce.sh` that re-runs one target
and diffs the verdict. Call it **hash-manifested**, not "signed".

### K. Cheap extras — P2

- A generated CI workflow that replays each fix's PoV on future commits.
- Memory speed-up A/B (same weakness class fixed a second time, cheaper).
- Wire procedural memory into routing (it records today; nothing reads it).
- Correct the docs that say "only 3 of 44 are externally sourced": the figure is **11 of 44**.

### L. Held-out validation — P0 — TODO

This is our final exam for "drag and drop any repo", and it only means something if we do not
tune on it.

- **Pre-register** 4 libraries before running anything, in `tests/heldout/PLAN.md`: C, under
  ~50k lines, flat or Makefile build, and a published memory-safety fix in git history.
  **Verify each choice** (build works, the fixed and vulnerable commits exist) before listing it.
- Use them to find general failures, but **fix causes, not targets**: any change must also
  pass the 44-target regression suite, and no target-specific code is allowed.
- Report them separately from the main corpus, including every failure and its reason.
- Success is not "all green". It is: **no unhandled crash, no silently skipped gate, and a clear
  reason for every case we could not prove.**

---

## 6. Build order

Ordered by dependency and risk. Each milestone has an exit criterion we can check.

| Milestone | Work | Exit criterion |
|---|---|---|
| **M0 Foundations** | B: model pull, client works against Ollama (JSON schema, `num_ctx`, `seed`); J: manifest + tool versions; `--events` flag in `benchmark.py` | Local model answers a Critic-style structured request; a run directory carries a manifest |
| **M1 Live surface** | D: FastAPI server, tool health, measured results, run benchmark, special cases (cheat detector, unit tests) | Cold start → open page → run cheat detector and a 3-target benchmark, both streaming live |
| **M2 Autonomy** | A1–A4 on seen targets first | One repo with no hand-written harness goes to a PoV-proven, accepted patch, PoV gate PASS |
| **M3 Drop a repo** | D panel 5 wired to A; sandbox F (required before any upload runs) | Drop a repo → live timeline → patch or an honest "unproven: reason"; a build that opens a socket is denied |
| **M4 Verifier** | E: ≥ 10 cheat classes and the patch policy gate | Detection rate published; every slipped cheat fixed or disclosed |
| **M5 Evidence breadth** | C: zlib, libpng, one embedded-style target; G spike; I | Each new defect validated in both directions; G go/no-go recorded |
| **M6 Exam and freeze** | L held-out validation; one full sweep; regenerate every document and the dashboard from that run | All of §8 satisfied |

No full benchmark sweeps before M6; use targeted re-runs. One full sweep at the end, and every
document regenerated from that single run directory.

---

## 7. Do not do

- No heavyweight UI stack, queue, database or GPU cluster. The dashboard is one FastAPI file
  and one HTML page.
- No "formal proof" wording for anything CBMC did not discharge.
- No unverified CVE IDs in slides: check each against upstream first.
- No ablation study (ruled out earlier). Baselines such as "gates alone vs gates plus
  hardening" are shown by the cheat suite.
- No full benchmark sweeps until the build is done; use targeted re-runs.
- No number in any document that is not in the final run directory.

---

## 8. Definition of done (the "perfect solution" bar)

All of these, each with its number:

| Area | Bar |
|---|---|
| **Autonomy** | On the held-out set: no unhandled exception; 0 silently skipped gates; every unproven case carries a written reason; at least one accepted, PoV-proven, hardened patch on a library we never tuned on |
| **Local model** | Full table: pass rate, time per target, tokens/s, peak RSS, $0, side by side with the cloud model, published as measured even if worse |
| **Dashboard** | Cold-start test passes (§5 D acceptance); shows only run-produced data; sandboxed uploads |
| **Verifier** | ≥ 10 cheat classes, detection rate reported, every slip fixed or disclosed; patch policy gate with a test per rule |
| **Real defects** | ≥ 5 published defects (cJSON ×3 + zlib + libpng), each validated both directions, each accepted + PoV-proven + hardened |
| **Formal** | One bounded proof on a real fix **or** a recorded no-go; the 3 synthetic proofs remain |
| **Reproducibility** | Every run directory has a manifest, tool versions, and a `reproduce.sh` that re-derives one verdict |
| **Safety** | Sandbox denial test passes; injection scrub test passes |
| **Honesty** | Every document regenerated from one run; CI beside every rate; 33 / 11 provenance stated; "Not measured" list current |
| **Quality** | `pytest` green; new modules each have tests; no TODO left in a code path the demo touches |

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Build detection for arbitrary repos is hard | Support flat `.c`, Makefile and CMake only; otherwise require `--build-cmd` and fail with a clear message. Never guess silently |
| 7B local model is too weak for real CVEs | Publish the measured result; the gates keep it safe; test 14B only if quality is the bottleneck |
| Fanless Air throttles during long local runs | Time-box local sweeps, run plugged in, measure and report sustained tokens/s |
| CBMC on real code hits modelling limits | 2-hour spike with a go/no-go; keep the synthetic proofs; never half-claim |
| Uploaded code is hostile | Sandbox before uploads are accepted; bind to localhost; size and path guards |
| Scope creep | Anything not in §5 is out; P2 items only when M0–M5 are done |
| Overfitting to our own corpus | Held-out validation (L) with a pre-registered list |

---

## 10. Status log

| Item | Status | Note |
|---|---|---|
| Model `qwen2.5-coder:7b` + derived `kavach-coder:7b` | **DONE** | 4.7 GB; Modelfile in `config/ollama/` |
| Local model readiness (client, JSON schema, speed, memory) | **DONE** | 15.2 tok/s, 4,882 MB, schema call works |
| Plan rewritten (pre-event scope) | **DONE** | |
| Structured events (`src/events.py`, `benchmark.py --events`) | **DONE** | shared by the dashboard and the future autonomous mode |
| D dashboard (FastAPI) | **DONE** | 56+ tests; Drop view runs auto mode (fuzz seconds, repair toggle) and shows crash, hardening and diff; verified through the API on local Ollama |
| B provider comparison | **DONE, measured** | cloud gpt-4o-mini vs a *remote hosted* Qwen2.5-Coder-14B (NOT on-device, not air-gapped). Synthetic 10: cloud 10/10, Qwen 9/10 (SYN-05 passed the gates but hardening falsified it; an earlier identical Qwen run was 10/10, so run-to-run variance is real). Real CVE 3: cloud 2/3, Qwen 3/3. Single runs, n small, no significance claim. Tables: `reports/compare_synthetic.md`, `reports/compare_real_cve.md`. On-device 7B benchmark still pending |
| A autonomous mode | **DONE, measured on 3 targets** | ingest → scan → (optional `--surface N` public-parser fuzzing) → harness → sanitizer build in sandbox → reach judge → fuzz → triage → repair → re-fuzz + differential. Demo double-free proven on local Qwen-7B ($0). **cJSON v1.7.10, OpenAI gpt-4o-mini, no hand-written PoV or root cause: `--surface` fuzzing found the real CVE-2019-11835 overflow in `cJSON_Minify` (cJSON.c:2642) and the patch was `proven` in 2 of 2 runs (133-160 s, ~$0.01), hardening: 137-input differential preserved, re-fuzz clean.** Semgrep alone missed it (it flagged print code). Fixes made on the way: hung-binary gates (SIGKILL timeout; alarm is swallowed by libFuzzer), replay-oracle trailing-newline bug, PoV gate replays every crash in the cluster plus same-line variants, root-cause brief in the prompt, re-fuzz in fork mode with a pre-existing second bug reported as a separate finding instead of blamed on the patch, hardening retry. Limits: `proven` = survived 137-input differential + 15-20 s re-fuzz, not a formal proof; post-scan gate is skipped for uploads; 7B local repair is slow; 1 library so far (cJSON), not yet a held-out one |
| A2 adaptive repair strategy | **DONE, measured** | `--strategy adaptive`: alpha (3 tries) -> beta (3 tries, told what alpha tried) -> gamma on a stronger model (5 tries, told everything); agents keep their names, delta is the critic. Escalation model is probed per API key (this key: gpt-4.1-mini only), never assumed. A/B on OpenAI, same targets, same flags: synthetic 10: ensemble 10/10, 43 model calls, $0.0101 vs adaptive 10/10, 11 calls, $0.0043; real CVE 3: ensemble 3/3, 33 calls, $0.0222 vs adaptive 3/3, 9 calls, $0.0068 (**-74% calls, -55..-70% cost**, wall time -10..15%). Cost: mean patch size grows (3.6->4.9 and 2.3->4.3 lines) because the ensemble picked the smallest of three. Hard case (auto-mode cJSON_Minify): proven 3/3 after a probe fix (an unusable gpt-4o had crashed tier 3 once). Single runs, small n. Default: adaptive in auto mode, ensemble in the benchmark (published numbers stay comparable) |
| J reproducibility bundle | **DONE, bug fixed** | bundle present in run dirs; `reproduce.sh` used to print "reproduced" when the re-run never ran (wrong interpreter); now exits 3 unless a new run dir is produced; test added |
| E cheats + patch policy | **DONE, measured** | policy gate: 10/10 synthetic still pass, 7/7 PoV-proven; red-team: 11/11 cheats caught, honest fix passes every layer (policy 6, gates 3, hardening 9; the execution gates alone catch none) |
| C zlib / libpng | NOT STARTED | zlib driver deferred to the Mac; libpng still needs the CVE verified |
| F sandbox + injection scrub | **DONE, measured** | macOS `sandbox-exec`; network-denial test has a positive control; SYN-06 passes under `required` (wall 49-58 s vs 36-37 s off, n=2, includes cloud model latency) |
| G CBMC spike | NOT STARTED | deferred to the Mac |
| H defence-domain page | DONE (doc) | `docs/defence_domain.md`; no target named yet |
| I detection precision/recall | CODE WRITTEN, run pending | `tests/benchmarks/detection_eval.py`; needs the Juliet C suite downloaded |
| K extras | CODE WRITTEN | CI workflow generator, procedural memory routing (memory on only), "11 of 44" corrected in benchmark.md |
| L held-out validation | TEMPLATE + RUNNER | `tests/heldout/PLAN.md` not yet registered: libraries must be verified first |

Handoff and test steps for the Mac: `MAC_TEST_HANDOFF.md`.
