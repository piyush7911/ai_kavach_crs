# AI Kavach — Detection (the FIND stage)

Detection is the core of the system and it is **static-first and deterministic**. An LLM is **not** the bug
finder: across 13 detection sources, exactly one is model-assisted, and even there the model only *proposes*
a parameter or class for a route the static/HTTP layers could not reach — a deterministic oracle still
decides whether anything is real. The breadth comes from rules, taint graphs and mined data, not from asking
a model "is this vulnerable?".

## 1. By the numbers

| Asset | Count |
|---|---|
| Detection sources (candidate generators) | **13** |
| Vulnerability classes the system can confirm | **32** |
| Community taint/pattern rules vendored offline (Opengrep) | **2,069** |
| — Python / JavaScript / Java / Ruby / Go / PHP | 376 / 182 / 127 / 92 / 82 / 61 |
| Our own clean-license Semgrep/taint rules | **260** (8 rule files) |
| Injection/OOB oracle families (source→HTTP confirmation) | **11** classes |
| Mined per-class technique vocabularies (from Strix skills) | **29** files |
| IDOR/BOLA vocabulary (ownership refs / check markers / knobs / id-forms) | 25 / 21 / 7 / 11 |
| Parameter-discovery wordlist (hidden-param names) | **160** |
| JS platform knowledge (sink modules / request shapes / ignore-roots) | 8 / 13 / 18 |
| Detection sources that use an LLM | **1 of 13** (fallback, proposer only, 7-class allowlist) |

Languages covered by source-level detection: **Python, JavaScript, Java, Ruby, Go, PHP** (rule corpus) plus
first-party flow analysis for JS and tree-sitter/Semgrep for Python/Java. HTTP-level detection is
language-agnostic (works on any backend).

## 2. The 13 detection sources

Grouped by how they look at the target. Every source emits *candidates*; confirmation is a separate stage.

### A. Source-level — static analysis & taint (white box, needs `--target`)
1. **Per-language static** (`src/{jsauto,pyauto,javaauto}/static.py`): our own analyzers — a JS dataflow
   engine driven by `config/js_knowledge.json` (8 sink modules, 13 request shapes), and tree-sitter +
   Semgrep for Python/Java. **260 first-party rules** across 8 files.
2. **Opengrep community corpus** (`--opengrep`): **2,069 taint/pattern rules** across 6 languages, run with
   inter-procedural taint, language-matched to the target, normalized to our classes, with the tainted
   parameter extracted from the dataflow trace. Cached by source-tree fingerprint for instant re-runs.
3. **Joern cross-file taint** (`--joern` / `--joern-run`): a code-property-graph taint engine that follows
   source→sink across functions and files — flows per-language rules miss. Anchored to the handler for route
   correlation.
4. **API-misuse literals** (`--misuse`): 4 FP-safe rule classes (weak hash, weak cipher, weak random,
   insecure cookie flags) matched only on *direct* literals (never config defaults) — emitted **confirmed**
   (the literal is the proof).

### B. HTTP-level — black-box probing & oracles (needs `--url`, language-agnostic)
5. **Parameter discovery** (`src/pyauto/param_discovery.py`): the recall engine — a **160-name** wordlist
   probed by chunked binary search (~50-60 requests cover the list), finding **un-echoed** parameters on
   auth-gated routes by response-diff, 0-FP via a same-size junk baseline.
6. **Live HTTP oracles** (`--live`): ~15 deterministic checks (headers, cookies, CORS, host-header,
   rate-limit, enumeration, JWT alg/secret/expiry, CSRF, reflected-XSS, open-redirect, mass-assignment,
   cache-poisoning) that confirm directly over HTTP.
7. **IDOR/BOLA** (`--idor`): route-map + a **25**-name ownership vocabulary and **21** ownership-check
   markers; flags object-reference routes lacking a visible check, for the two-user oracle.
8. **GraphQL** (auto): introspection maps resolvers; object-id queries become BOLA candidates.
9. **Schema fuzzing** (`--schema-fuzz`): OpenAPI-driven valid requests; any 5xx is a confirmed server fault.
10. **Request smuggling** (`--smuggle`): CL.TE timing probe (candidate-tier).

### C. External scanner ingestion (optional, re-confirmed by our oracle)
11-13. **ZAP / Nuclei / Trivy** reports ingested as candidates; ZAP/Nuclei alerts are re-tested by our own
oracle so their breadth becomes our proof and their false positives never confirm.

## 3. Class coverage (32 confirmable classes)

`injection, sql-injection, nosql-injection, command-injection, path-traversal, ssrf, xxe,
insecure-deserialization, open-redirect, xss, xss-reflected, ssti, eval-injection, idor,
broken-object-level-auth, mass-assignment, excessive-data-exposure, sensitive-data-exposure,
user-enumeration, clickjacking, cookie-flags, cookie-samesite, cors-misconfig, csrf-missing, no-rate-limit,
host-header-reflection, header-injection, predictable-session-id, jwt-none-alg, jwt-weak-secret,
jwt-no-expiry, web-cache-poisoning, server-error` (plus `http-request-smuggling` at candidate tier).

Of these, **11 injection/OOB classes** are confirmed by a source→HTTP bridge (sql/nosql/injection, xss,
command-injection, path-traversal, ssrf, open-redirect, xxe, insecure-deserialization, ssti); the remainder
by the live/metamorphic/fact oracles.

## 4. How little the LLM does

Only **1 of 13** sources is model-assisted — the gap-route proposer (`src/pyauto/llm_attacks.py`,
`--llm-attacks`). It activates **only for routes that static + parameter discovery could not give a
parameter**, and is restricted to a **7-class allowlist** (`sql-injection, nosql-injection,
command-injection, path-traversal, ssrf, open-redirect, xss`) — classes a deterministic oracle can confirm.
The model proposes a `{param, class}` or shapes an OOB payload; it never labels a finding real. Everything
it suggests is then replayed by an oracle, so a wrong guess simply fails to confirm and stays a candidate.
In a typical run against a well-covered target the LLM proposes **zero** (the static + discovery layers
already have the parameters). The system runs end-to-end with the LLM disabled — detection does not depend
on it.

## 5. Empirical candidate yields (observed)

| target | language | static/taint candidates | note |
|---|---|---|---|
| DVWA | PHP | **92** (Opengrep corpus) | SQLi, exec, unserialize, eval, file-inclusion, weak-crypto |
| VulnerableApp | Java | **375** cross-file taint flows (Joern) | injection classes across controllers |
| NodeGoat | JavaScript | **15** (first-party static) | + 2 IDOR, eval/nosql/ssrf/xss flows |
| Ruby demo | Ruby | dynamic-confirmed | SQLi + command-injection (corpus thin for the sink shape) |

These are *candidate* counts — the FIND stage's reach. Precision is enforced downstream: only candidates a
replayed exploit (or a deterministic fact) confirms are ever claimed.

## 6. Why static-first

- **Precision**: a candidate is cheap and never claimed; the oracle, not a model, decides — so breadth costs
  nothing in false positives.
- **Air-gap**: 2,069 + 260 rules and all vocabularies are vendored offline; no model call is needed to find.
- **Speed**: rules + cached CPG + chunked parameter discovery; the slow, model-bound path is avoided for
  detection.
- **Auditability**: every candidate names a file/line or a route+param — deterministic and reviewable, not a
  model's opinion.
- **Generality**: adding a language or class is adding *data* (rules, vocab), not code or prompts.

See `docs/ARCHITECTURE.md` for the full pipeline (FIND → PROVE → FIX → REPORT).
