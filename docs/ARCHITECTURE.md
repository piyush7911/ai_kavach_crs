# AI Kavach CRS — Architecture (web application track)

> Written for the finale jury/mentors and for teammates or new developers reading the code for the first
> time. It describes the **web-application Cyber Reasoning System** ("kavach") that runs in the finale: how
> it finds vulnerabilities, proves them by exploitation, fixes them, and reports — language-agnostically and
> without false positives. A separate, earlier binary/C-fuzzing path also exists in the tree; it is **not**
> the finale system and is listed, clearly separated, in Appendix B.

---

## 1. Purpose & finale scope

The finale runs our system **autonomously against an unknown web application** provisioned on an isolated
per-team VM, with no manual developer intervention, scored on four jury parameters: autonomous bug discovery
(precision & efficiency), automated patch generation (quality, correctness, speed), regression proof, and
scalability/architecture.

Kavach is a single pipeline — **FIND → PROVE → FIX → REPORT** — driven by one command
(`python -m benchmarks.kavach`). It treats the target as a black box over HTTP for confirmation and, when a
source tree is provided, as a white box for candidate generation. It supports JavaScript, Python, Java, PHP
and Ruby targets (see §11).

## 2. Design invariants (the rules nothing may break)

1. **Propose freely; the oracle/gate decides.** Any component (static rules, taint engines, an LLM, mined
   vocabularies, external scanners) may *propose* a candidate. A finding is only `confirmed` when a replayed
   exploit fires or a deterministic fact is observed. Nothing an LLM "thinks" is ever asserted on its own.
2. **Zero false positives in the claimed tier.** Only `confirmed` findings are reported as vulnerabilities
   (the CSV). Everything else stays `candidate` in the JSON, never claimed. A reporting gate (§6.3) enforces
   this structurally. Signals that cannot be a clean proof (e.g. request-smuggling timing) stay `candidate`.
3. **Language-agnostic.** Confirmation is pure HTTP (an SQLi differential does not care whether the backend
   is PHP or Java). Detection breadth comes from per-language rule/taint data, not hardcoded logic.
4. **Air-gapped / local-only.** No internet at run time. Local models over an OpenAI-compatible HTTP endpoint
   (`OPENAI_BASE_URL`), no SDK dependency in the probe path. Dependency fixes are advisory (never re-resolved).
5. **No hardcoding of a target.** The engine carries no app's credentials, routes, or benchmark name. The
   oracle engine lives at `benchmarks/oracle_engine.py` (neutral); app specifics are supplied via `--auth`,
   `--routes`, and the target URL.

## 3. Pipeline overview

```
            ┌───────── FIND (candidates) ─────────┐   ┌──── PROVE (confirm) ────┐   ┌─ FIX ─┐   ┌ REPORT ┐
source ───► static (per-lang) ─┐                   │   │ injection/OOB oracles   │   │template│   │  CSV   │
tree        opengrep corpus ───┤                   │   │ (differential/marker/   │   │ config │   │  JSON  │
            Joern taint ───────┤► candidates ──────┼──►│  OOB/two-user)          ├──►│ CEGIS  ├──►│ ledger │
            route-map ─────────┤   (file/func/      │   │ live HTTP oracles       │   │ LLM    │   │ exch.  │
            misuse literals ───┤    class, param)   │   │ reporting gate +        │   │(gated) │   │ llm    │
URL ──────► param-discovery ───┤                   │   │ severity honesty +      │   └────────┘   │ run.js │
            IDOR / GraphQL ─────┤                   │   │ candidate sanity        │                └────────┘
            ZAP/Nuclei/Trivy ──┘                   │   └─────────────────────────┘
```

Exact stage order in `main()`: LLM-trace init → static(`--target`) → dynamic discover+probe(`--url`) →
live(`--live`) → ZAP/Nuclei → Trivy → opengrep(`--opengrep`) → Joern(`--joern-run`/`--joern`) →
misuse(`--misuse`) → IDOR(`--idor`) → smuggling(`--smuggle`) → schema-fuzz(`--schema-fuzz`) → GraphQL(auto on
`--url`) → correlate+LLM bridge → candidate sanity → de-dup → **FIX**(`--fix`) → reporting gate → outputs.

## 4. CLI entry — `python -m benchmarks.kavach`

| flag | effect |
|---|---|
| `--target <dir>` | source tree (stack auto-detected); drives static, opengrep, misuse, correlate, fix |
| `--url <base>` | running target; drives discovery, oracles, live checks, IDOR/GraphQL/smuggle/schema-fuzz |
| `--routes <json>` | framework route map (from `exp/scripts/route_map.py`) — drives `--live`, `--idor`, correlate |
| `--auth <json>` | auth spec (roles→creds, login shape, CSRF field, cookies) → authenticated confirmation |
| `--live` | language-agnostic live HTTP oracles (headers/cookies/CORS/JWT/rate-limit/enumeration/XSS/redirect/mass-assign/cache-poison) |
| `--misuse` | FP-safe source literals (weak hash/cipher/random, cookie flags) as confirmed findings |
| `--idor` | IDOR/BOLA candidates from the route map; path-id routes auto-confirmed |
| `--smuggle` | HTTP request-smuggling timing probe (candidate-tier; isolated VM only) |
| `--schema-fuzz` | OpenAPI-driven 5xx-on-valid-input server faults |
| `--opengrep [--opengrep-rules]` | community taint corpus as candidates (cached by tree fingerprint) |
| `--joern <tsv>` / `--joern-run` | Joern cross-file taint (pre-built TSV, or build+run if joern is vendored) |
| `--zap / --nuclei / --trivy <report>` | ingest an external scanner's report as candidates, re-confirm via our oracle |
| `--llm-surface / --llm-attacks` | LLM proposes routes / {param,class} for gap routes (oracle still confirms) |
| `--fix [--run-cmd --seed]` | template-first + config-remediation + CEGIS LLM-fallback patching |
| `--out <file.json>` | write findings JSON + `<file>.csv` + `coverage.json` + `run.json` (+ exchanges/llm_trace) |

Example (full run, authenticated): `kavach --target ./app --url http://10.0.0.5:8080 --routes routes.json
--auth auth.json --live --misuse --idor --opengrep --fix --out reports/report.json`.

Models: set `OPENAI_BASE_URL` + `MODEL_PROBE` for any LLM stage (see §9.4).

---

## 5. FIND — candidate sources

All of these emit `Finding` objects (§10). Code-location sources carry `(file, function, class, param?)`;
HTTP sources carry `(route, param?)`. None of them *claim* a vulnerability — they feed PROVE.

- **Per-language static** (`src/{jsauto,pyauto,javaauto}/static.py`, auto-selected by `detect_stack`): our own
  pattern/flow rules per backend. JS has a flow engine + `config/js_knowledge.json`; Python/Java use
  tree-sitter + Semgrep rule files. Produces code-location candidates.
- **Opengrep corpus** (`benchmarks/scanners/opengrep.py`, `--opengrep`): the vendored community taint corpus
  (~890 rules, language-matched sub-dirs) run by Opengrep (inter-procedural taint). Rule hits are normalized
  to our classes (`_normalize_class`) and the tainted parameter is extracted from the dataflow trace. Cached
  by source-tree fingerprint (`src/autonomy/scan_cache.py`) so sprint re-runs reuse results.
- **Joern taint** (`benchmarks/scanners/joern.py`): cross-file source→sink flows. `--joern <tsv>` ingests a
  pre-built TSV; `--joern-run` builds the CPG (`{java,py,js}src2cpg`) and runs `exp/scripts/joern_taint.sc`
  itself when joern is on PATH or vendored at `exp/third_party/joern` (tolerant: no joern ⇒ skip). A flow is
  anchored to its **source handler** (for route correlation), with the sink kept in evidence.
- **Route map** (`exp/scripts/route_map.py` → `knowledge/routes_*.json`): deterministic entry-point extraction
  (OpenAPI/Spring/Express/Flask/servlet) — `(method, path, params, file, function)`. Drives `--live`, `--idor`
  and the correlate bridge. Framework-aware, no app names.
- **Misuse literals** (`benchmarks/scanners/misuse.py`, `--misuse`): FP-safe *direct* source literals only —
  `getInstance("MD5")`, `Cipher.getInstance("DES…")`, `new Random()`, `setSecure(false)` — never
  `getProperty(…,"MD5")` defaults (which caused crypto FPs). Emitted as **confirmed** (the literal is the proof).
- **Parameter discovery** (`src/pyauto/param_discovery.py`): the recall+speed lever. Arjun/x8 chunked
  binary-search — packs many candidate names into one request, binary-splits the chunk whose response
  differs; a same-size junk baseline sampled twice makes it 0-FP (param-count/jitter cancels). Finds
  **un-echoed** params on auth-gated routes (response-diff, not reflection). Runs concurrently across routes
  under the global rate cap.
- **IDOR/BOLA** (`benchmarks/scanners/idor.py`, `--idor`): from the route map + mined vocab
  (`config/idor_fields.json`): ownership-reference params, id-suffix, resource keys, expansion knobs, path-id
  segments, with **function-scoped** ownership-check suppression. Recall-first; the two-user oracle gates it.
- **GraphQL** (`benchmarks/scanners/graphql.py`, auto on `--url`): detects the endpoint, runs introspection,
  emits a BOLA candidate per root query taking an object id (→ two-user oracle). Silent if no GraphQL.
- **External scanners** (`benchmarks/scanners/{zap,nuclei,trivy}.py`): ingest a report as candidates; ZAP/
  Nuclei alerts are re-tested by our oracle (`confirm_candidates`) so their breadth becomes our proof and
  their false positives simply never confirm. Trivy (deps/CVE/IaC/secrets) is source-level, advisory.
- **LLM proposers** (`src/pyauto/llm_{surface,attacks}.py`, `--llm-surface/--llm-attacks`): the model reads
  HTML/JS or handler source and proposes routes / {param, class} for *gap* routes. Allowlisted to classes an
  oracle can confirm; the oracle still decides (plan 010).

## 6. PROVE — the oracle engine, the gate, and the honesty layers

### 6.1 Oracle engine (`benchmarks/oracle_engine.py`, neutral re-export `benchmarks/oracles.py`)
`run_exploit(base_url, exploit)` dispatches on the exploit's shape; every family is self-validating:

| oracle | class(es) | how it confirms (0-FP rationale) |
|---|---|---|
| **differential** | sql/nosql injection | true (tautology) vs false (contradiction) responses differ; a benign control is sent too, so reflection alone can't explain the flip. `_norm` strips digits so volatile data isn't a difference |
| **marker** | command-injection, path-traversal, reflected-XSS, open-redirect, SSTI | the success signal is the *result* of the attack, absent from the payload (`;expr 31337+1`→`31338`; `../../etc/passwd`→`root:…:0:0`; SSTI `7*191`→`1337`; unescaped tag reflected in HTML; evil host in `Location`) |
| **OOB callback** | SSRF, XXE, insecure-deserialization | the target is made to fetch a one-time loopback listener; a hit proves server-side execution. Air-gap-safe (loopback only). LLM may *shape* an app-schema payload — the callback, not the LLM, decides |
| **two-user / metamorphic** | IDOR, BOLA, access-control, write-IDOR | same request as an authorized vs unauthorized role; or foreign vs own object id returns different data; or verify-after-write (a marker written as non-owner is read back) |
| **content/behavioral** | mass-assignment, data-exposure, enumeration, rate-limit, cookie/CORS/clickjacking/CSRF/JWT, cache-poisoning | a fact (header absent, cookie flag off), a unique-marker read-back (mass-assign, cache-poison), a forged-token replay (JWT weak secret), or a behavioral count (no lockout) |

Marker families URL-encode path-param payloads; XSS requires an HTML content-type; data-exposure requires a
real `"key":"value"` (not an HTML form field — a past FP). Request-smuggling (`src/pyauto/smuggling.py`) is a
CL.TE timing probe → **candidate** only (timing is not a clean proof), confirmed on 2/2 trials past margin.

### 6.2 Live stage (`src/pyauto/live_probes.py`, `--live`)
Pure-HTTP, language-agnostic oracles over the route list. App-global config classes (clickjacking, cookie
flags, CORS, JWT, CSRF, rate-limit) collapse to **one** finding with an affected-route count (not spam per
route). Every live finding records its actual request for the evidence trail.

### 6.3 Correlate bridge + reporting gate + honesty
- **Correlate** (`src/pyauto/correlate.py`): maps a code-location candidate to its live route — exactly via a
  route map (`correlate_with_routemap`, keyed by `(file-basename, function)`), or heuristically; the wire
  param is resolved from source (`src/pyauto/param_source.py`, constants resolved file-local-first), then the
  oracle confirms. This is how a Joern/Opengrep/static candidate becomes a confirmed, replayable bug with no
  LLM. Deduplicated by `(route, param, class)`.
- **Candidate sanity** (`src/autonomy/candidate_sanity.py`): before reporting, a static candidate whose cited
  `file:line`/function does not exist is **dropped** (anti-hallucination); an injection candidate with no
  ingress is demoted. Confirmed findings (an oracle fired) are exempt.
- **Reporting gate** (`src/autonomy/finding_gate.py`): a finding stays `confirmed` only if it carries poc/
  evidence, counterevidence, confidence (+rationale when not high), severity-change conditions, and
  fix_verification when a patch is attached. Fields are filled *from the oracle*, not model self-attestation;
  anything that can't satisfy the gate is downgraded to `candidate`. (Adapted from Strix's schema.)
- **Severity honesty** (`src/autonomy/severity.py`): only ever *lowers*/flags — self-refuting rationale and
  auth preconditions lower a tier; no-consequence classes floor to low; hedges in a confirmed claim are
  flagged. Never inflates.

## 7. FIX — template-first, then gated LLM

`_fix_stage` in `benchmarks/kavach.py` (`--fix`, needs `--target`):

1. **Templates** (`src/autonomy/template_patch.py`, deterministic, no LLM): pure literal swaps on scratch
   copies, re-verified (weak literal gone), line-scoped so a fix can't falsely claim a sibling site:
   `getInstance("MD5"/"SHA-1")`→`"SHA-256"`, `hashlib.md5/sha1(`→`sha256(`, `setSecure/HttpOnly(false)`→`true`,
   `new Random()`→`new java.security.SecureRandom()`. Dependency findings are **refused** (advisory-only).
2. **Config remediation** (`src/autonomy/config_fixes.py`): for the confirmed live classes that have no code
   sink (clickjacking/cookie/CORS/CSRF/rate-limit/JWT), attach the exact **framework-aware** fix snippet
   (express/spring/flask/django/rails/generic, detected from the tree) + how to verify. RoE allows config fixes.
3. **CEGIS LLM-fallback** (`src/{pyauto,javaauto,jsauto}/repair.py`, needs `--url` + `OPENAI_BASE_URL`; py/js
   also need `--run-cmd`): for confirmed code-location findings with no template, the model rewrites the one
   function; the patch is spliced (tree-sitter) and passed through a **four-way gate**:
   - **PoV-gone** — the confirming exploit no longer fires on the patched build;
   - **regression** — recorded good traffic (observed routes, `src/autonomy/differential_validation.py`) still
     returns the same responses (behavior preserved — the regression set is derived from traffic, not invented);
   - **static re-scan** (`src/autonomy/rescan_gate.py`) — the taint scanner finds the vuln *class* gone from the
     patched file (not just the one input); if not, the failure is fed back as a counterexample;
   - a failed PoV feeds the concrete attacking request back to the model (CEGIS), not a vague "try again".
   After acceptance, **sibling-sink review** re-scans for the same class at other files and surfaces any twins
   as candidates. Java builds `--offline` (incremental daemon; no finale network hang).

---

## 8. REPORT — artifacts (all in the `--out` directory)

| file | content |
|---|---|
| `<out>.csv` | **the deliverable vuln report** (`src/autonomy/report_csv.py`): confirmed only, columns *S. No. / Vulnerability Title / Severity / Description / Code Location / Path / Steps to Reproduce (Evidence)*, sorted Critical→Low, evidence = payload + request + expected-vs-observed + logged exchange ids |
| `<out>.json` | all findings incl. candidates (full `Finding` dicts) + coverage |
| `coverage.json` | evidenced ledger (`src/autonomy/coverage_ledger.py`): every (route,class) examined → `reported / no_issue_found / ruled_out / not_applicable / needs_follow_up`, evidence mandatory for the last three ("0 findings is never 'clean'") |
| `exchanges.jsonl` | every confirmed finding's attack request, numeric id (`src/autonomy/exchange_log.py`) — findings cite ids; `verify()` rejects fabricated ones |
| `llm_trace.jsonl` | every probe-LLM prompt+response+model+timing |
| `run.json` | manifest/index: target, timestamp, confirmed/candidate counts (by class + severity), coverage, artifact paths |

Together these satisfy the RoE audit requirement ("all runs, fuzzing logs, LLM query traces, patch logs").

## 9. Cross-cutting

- **9.1 Concurrency & throttle** (`benchmarks/oracle_engine._throttle`): a lock-serialized global request-rate
  cap (RoE "throttled fuzzing"), tunable via `KAVACH_MIN_INTERVAL`, holds under any worker count.
  `param_discovery.parallel_map` runs independent work concurrently (payoff on a latency-bound remote VM; on
  loopback the rate cap dominates, so the rate knob is the lever).
- **9.2 Caching** (`src/autonomy/scan_cache.py`): source-tree fingerprint (path+size+mtime) keys cached
  Opengrep results; unchanged tree ⇒ instant reuse, any change ⇒ fresh scan. Cuts the sprint re-run loop.
- **9.3 Auth** (`--auth` JSON → `Session._login_via_spec`): roles→creds, login path/fields, JSON or form,
  bearer-token (VAmPI JWT) or cookie, **CSRF-aware** (`csrf_field` scraped from the login page — DVWA
  `user_token`, Django/Rails tokens), `extra_fields`, and preset `cookies` (e.g. DVWA `security=low`).
  Specs: `config/nodegoat_auth.json`, `config/dvwa_auth.json`.
- **9.4 LLM wiring** (`benchmarks/kavach._build_probe_llm`): OpenAI-compatible `/chat/completions` over
  stdlib `urllib` — no SDK in the probe path, air-gap-install-free. Env: `OPENAI_BASE_URL`, `MODEL_PROBE`
  (falls back to `MODEL`), key in env only. (The legacy orchestrator in Appendix B uses the `openai` SDK.)
- **9.5 Air-gap**: loopback-only OOB; dependency fixes advisory; Java `--offline`; models local.

## 10. Data model & config

`Finding` (`src/jsauto/findings.py`): `id, source, klass, file, line, function, cwe, owasp, severity,
confidence, message, status (candidate|confirmed), reason, evidence{route,param,detail,request,…},
exploit (replayable), stride/reachability/exploitability/cvss/poc, patch, patch_note, counterevidence,
confidence_rationale, severity_change_conditions, evidence_text, fix_verification, http_exchange_ids`.
`SECURITY_PROFILE` maps each class → (STRIDE, exploitability, CVSS); `apply_security`/`build_poc` fill
enrichment on confirmed findings.

Config (`config/`): `idor_fields.json` (IDOR vocab), `js_knowledge.json`/`js_probes.json`/`js_fix_guidance.json`
(JS backend), `semgrep/` (our clean-license taint rules), `*_auth.json` (auth specs), `advisories/` (offline
SCA data).

## 11. Language coverage (empirically proven)

| language | static detect | dynamic confirm (HTTP oracle) | shown on |
|---|---|---|---|
| JavaScript | yes (flow engine + rules) | yes | NodeGoat |
| Python | yes (tree-sitter + Semgrep) | yes | VAmPI |
| Java | yes (tree-sitter + Semgrep + Joern) | yes | VulnerableApp |
| PHP | yes (Opengrep corpus: 92 on DVWA) | yes (SQLi confirmed on DVWA) | DVWA (Docker) |
| Ruby | corpus gap for some sink shapes | yes (SQLi + command-injection confirmed) | Sinatra app (Docker) |

The confirmation oracle is identical across all five — it is pure HTTP. Detection breadth varies with the
available rule/taint data per language (Ruby's corpus is thin for some patterns; the dynamic oracle still
catches those).

## 12. RoE compliance

Own-instance only (no cross-tenant); throttled (global rate cap, no unthrottled fuzzing); non-destructive
oracles (expr markers, loopback OOB — never delete/wipe); code-level **or config** patches only, advisory for
dependencies, no persistence/backdoors; declared local model endpoints; full audit bundle (§8). Shared-state
oracles (cache-poisoning, request-smuggling) are enabled because the finale target is an **isolated per-team
VM** (see memory `finale-environment`).

## 13. Module map (web CRS)

- **Entry/orchestration**: `benchmarks/kavach.py` (the pipeline), `benchmarks/oracle_engine.py` +
  `benchmarks/oracles.py` (HTTP oracle engine + neutral facade).
- **FIND**: `src/{jsauto,pyauto,javaauto}/static.py`; `benchmarks/scanners/{opengrep,joern,misuse,idor,graphql,
  zap,nuclei,trivy}.py`; `src/pyauto/{param_discovery,param_source,llm_surface,llm_attacks,probes,correlate}.py`;
  `exp/scripts/route_map.py`.
- **PROVE**: `src/pyauto/{probes,live_probes,smuggling,schema_fuzz}.py`;
  `src/autonomy/{finding_gate,severity,candidate_sanity}.py`.
- **FIX**: `src/autonomy/{template_patch,config_fixes,differential_validation,rescan_gate}.py`;
  `src/{pyauto,javaauto,jsauto}/{repair,patch,runner}.py`.
- **REPORT**: `src/autonomy/{report_csv,coverage_ledger,exchange_log}.py`.
- **Shared**: `src/jsauto/findings.py` (`Finding` + profile); `config/`.

## 14. Limitations & honest gaps (as of this writing)

- **Authenticated confirmation needs `--auth`**: without a supplied spec, authed classes (IDOR, authed
  injection) stay `candidate` — the engine carries no app credentials by design. Proven end-to-end on DVWA
  with a spec; an unseeded target yields only unauthenticated/config confirmations.
- **Joern is one command only if vendored**: `--joern-run` no-ops when joern isn't installed; otherwise pass a
  pre-built TSV via `--joern`.
- **Ruby static** corpus is thin for some sink shapes (dynamic oracle still confirms).
- **Request-smuggling** is timing-based → candidate-tier only (never claimed confirmed).
- **New oracles** (SSTI, mass-assign, cache-poison, schema-fuzz) are unit-tested and shown to not
  false-positive on non-vulnerable targets; positive confirmations are proven for the injection/IDOR/live set.
- Business-logic, stored-XSS-via-render, and similar remain detect-only (no clean single-request oracle).

## 15. Quickstart

```bash
# source-only (static + taint candidates, cached):
python -m benchmarks.kavach --target ./app --opengrep --out reports/report.json

# black-box live (any language), with a route map + auth:
python -m benchmarks.kavach --url http://TARGET:PORT --routes routes.json --auth auth.json \
       --live --idor --schema-fuzz --out reports/report.json

# full find→prove→fix (source + live + patch), declared local model:
OPENAI_BASE_URL=http://MODELHOST:1234/v1 MODEL_PROBE=google/gemma-4-12b \
python -m benchmarks.kavach --target ./app --url http://TARGET:PORT --routes routes.json --auth auth.json \
       --misuse --idor --live --opengrep --fix --run-cmd "node server.js {port}" --out reports/report.json
```
Deliverable = `reports/report.csv`; full audit bundle alongside it (§8).

---

## Appendix A — Design lineage
Oracle/gate discipline and the candidate→confirmed bridge are ours; the reporting-gate schema, coverage
ledger, IDOR vocab and exchange-log ideas are adapted from Strix (Apache-2.0); severity-honesty rules from
Shannon (AGPL, ideas only); taint-rule mining and the Joern pilot from the `exp/` research. Patching draws on
TBar/TemVUR (templates) and CEGIS (counterexample-guided repair).

## Appendix B — Legacy binary/C-fuzzing path (NOT the web finale system)
An earlier CRS for C/C++ fuzzing lives under `src/{agent_orchestrator, analysis_engine, fuzz_pipeline,
patch_validator, context_engine}` and `src/main.py` (LangGraph-style agents + libFuzzer/AFL++/driller + CASR
triage; uses the `openai` SDK via `src/agent_orchestrator/llm_client.py`). It is retained for reference and
its own benchmarks; the web-application finale runs the kavach pipeline described above, not this path.
