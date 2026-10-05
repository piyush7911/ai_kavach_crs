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
| Dependency audit | **offline**: lockfile matched against a vendored advisory snapshot (400 KB, 7,241 advisories); identical to `npm audit` on NodeGoat (10/10 packages) |
| Track 1 (runner, manifest, PoVs, flows) | built by the other half; runtime needs MongoDB 4.4, which this Mac lacks |
| Genericity guards | rename-mutation tests, name tripwire, held-out app (DVNA) |

## Measured

- NodeGoat static detection: recall 8/11 (0.727), precision 0.81 (inflated by 10 dependency findings
  counting as hits; about 0.64 without them). Misses IDOR, XSS, CSRF: they need dynamic probes.
- DVNA (unseen, untuned, no model): 5 of 6 core injection classes found by some detector, 3 of 6 by flow alone.
- Local model: with thinking on, one short request took 118 s and returned nothing; off, 9.3 s.

## Not done / not measured

- **Gemma-assisted run on DVNA** (does the model classify `mathjs.eval`, `sequelize.query`, `libxmljs`?).
- **Dynamic probes**, JS repair (context, patch splicing, policy gate), audit log of model prompts.
- **Nothing runs end to end on a live app yet**: no MongoDB here.
- Last tests run: 289 passing, then more were added (offline deps, flow, informational secrets, more flow
  cases) and mostly not run since; two known gaps are marked as expected failures.
- Pre-installed `node_modules` are needed at the venue: `npm install` also hits the registry.
