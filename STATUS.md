# Where we are (2026-10-05)

First finale target: **OWASP NodeGoat** (Node.js, Express, MongoDB). Rules: own hardware, declared
models only, no unauthorised network (so **no npm registry**), real fixes that keep the app working.
Local model: `gemma4:12b`. Plan: [`NODEGOAT_PLAN.md`](NODEGOAT_PLAN.md). Interface:
[`benchmarks/nodegoat/CONTRACT.md`](benchmarks/nodegoat/CONTRACT.md).

## Built and checked

| Area | State |
|---|---|
| C pipeline (autonomous mode, adaptive repair, sandbox, hardening) | done; cJSON `cJSON_Minify` found and patched with no hand-written proof |
| JS static detection | 233 vendored Semgrep rules plus 7 generic Node rules, offline |
| Generic flow analysis (`src/jsauto/flow.py`) | entry points by role, cross-file taint, sinks from `config/js_knowledge.json`, model fallback for unknown calls |
| Dependency audit | **offline**: lockfile matched against a vendored advisory snapshot (400 KB, 7,216 advisories); identical to `npm audit` on NodeGoat (10/10 packages) |
| Track 1 (runner, manifest, PoVs, flows) | built by the other half; runtime needs MongoDB 4.4, which this Mac lacks |
| Genericity guards | rename-mutation tests, name tripwire, held-out app (DVNA) |

## Measured

- NodeGoat static detection: recall 8/11 (0.727), precision 0.81 (inflated by 10 dependency findings
  counting as hits; about 0.64 without them). Misses IDOR, XSS, CSRF: they need dynamic probes.
- DVNA (unseen, untuned): without a model 5 of 6 core injection classes found by some detector, 3 of 6 by flow alone; **with the local model classifying unknown calls, 6 of 6** (6 model calls, 84 s; one run, so not a guarantee).
- Local model: with thinking on, one short request took 118 s and returned nothing; off, 9.3 s.

## Written 2026-10-06, then run (only the new tests: 106 passed, 2 expected failures)

Running them found and fixed: a wrong test, two real bugs (advisory count, route-vs-helper evidence order) and a hard-coded runner name in the engine.

| Piece | Files | What it does |
|---|---|---|
| Audit trace + endpoint pinning | `llm_client.py` (`_create`), `tests/unit/test_llm_audit.py` | every model call is logged (prompt, response, tokens, errors) to `KAVACH_LLM_TRACE`; `KAVACH_ALLOWED_ENDPOINTS` / `KAVACH_ALLOWED_MODELS` refuse anything undeclared, also for escalation |
| JS patching | `src/jsauto/patch.py` | splice a function by syntax-tree range, parse check, patch policy (only the flagged function, size cap, no added code/shell execution, outbound calls, swallowed errors, time conditions, emptied function), dependency-bump vetting |
| Model context | `src/jsauto/context.py`, `config/js_fix_guidance.json` | what the model sees: class guidance, route, call chain, the function to fix |
| Probes | `src/jsauto/probes.py`, `config/js_probes.json` | describe a replayable exploit per finding (nothing is sent); classes without a usable oracle say why |
| Repair loop | `src/jsauto/repair.py`, `tests/unit/test_jsauto_repair_loop.py` | model -> splice -> policy -> start/replay/regress gates, rejections fed back; skipped gate is never a pass; dependency fixes are deterministic |
| Tests | `test_jsauto_repair.py`, `test_jsauto_more.py`, `test_jsauto_offline_deps.py` | around 100 cases in total |

## Not done / not measured

- **Nothing runs end to end on a live app yet**: no MongoDB here, so probes and the repair loop's gates have only been described and stubbed.
- JS hardening (exploit variants, re-run regression) is not written.
- Last full run: 396 passed, 2 expected failures (known gaps), 1 failure that was then fixed and re-run alone.
- Pre-installed `node_modules` are needed at the venue: `npm install` also hits the registry.
