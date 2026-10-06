# Joern pilot (2026-10-06)

Joern 4.0.649 (Apache-2.0 code property graph + taint engine), run on Java 25, macOS arm64. Installed only under
`exp/third_party/joern/`. Kavach (`src/`, `config/`) and the conda env are untouched. Nothing pushed.

Targets, in the order requested: NodeGoat (JS), VAmPI (Python), SasanLabs/VulnerableApp (Java).
One script (`scripts/joern_taint.sc`) serves all three languages; only the source and sink name tables differ.

## How it works
1. Build a code property graph per target (pysrc2cpg / jssrc2cpg / javasrc2cpg), 1-2 s each.
2. Sources = request inputs (`request.args`, `req.query`, `@RequestParam`, `getParameter`...). VAmPI routes through
   OpenAPI, so its path parameters are not request-object reads; `wide=true` treats function parameters as sources there.
3. Sinks = dangerous calls per class (SQL, command, path, XSS, XXE, LDAP, SSRF, deserialization, redirect, eval, NoSQL).
   Java sinks match on the resolved `methodFullName` (e.g. `java.lang.ProcessBuilder.<init>`). SQL sinks use only the first
   argument (the SQL text), so bound parameters are not sinks.
4. `reachableByFlows` finds source -> sink paths, across functions and files. Each path is one finding.
Scan time 4-5 s per target.

## Results (true bugs in taint scope / found / safe cases flagged)

| Target | Taint-scope true bugs | Kavach today | Joern |
|---|---|---|---|
| NodeGoat (5 of 12 labels are taint classes; the rest are IDOR, secrets, config, CSRF, ReDoS) | 5 | **5** | 3 (eval, ssrf, open-redirect) |
| VAmPI (1 of 10 labels is a taint class; the rest are logic/auth/config bugs) | 1 (SQLi) | 0 | **1** (SQLi, route handler -> model query, across 2 files, wide mode) |
| VulnerableApp: vulnerable levels in taint scope | 52 | 10 (TPR 0.19) | **46 (TPR 0.885)** |
| VulnerableApp: secure levels in taint scope flagged | 32 | 6 (FPR 0.19) | 19 (FPR 0.59) |
| VulnerableApp: TPR - FPR | | 0.005 | 0.291 |

Not in scope for taint analysis (neither tool is scored on them): VulnerableApp 83 vulnerable + 13 secure levels
(JWT, crypto, rate limiting, session, password reset, clickjacking, cache poisoning, IDOR...); VAmPI 9 of 10; NodeGoat 7 of 12.

VulnerableApp found by class (tp / fn / fp on secure levels): sql 9/0/2, xss 19/5/8, command 5/0/1, code 1/0/0,
deserialization 2/0/1, ldap 4/0/2, ssrf 4/0/1, xxe 2/1/4. Missed: UnrestrictedFileUpload levels 3-7 (file-upload
logic, not a source->sink flow) and XXE level 6.

## What I learned
- Joern finds real cross-file flows that pattern rules cannot (VAmPI SQLi, 45 of 52 VulnerableApp injection levels).
- Its false alarms are structural: it does not know that a validation branch (`if (x.contains("<")) return 400`), a
  custom encoder, or a parser hardening flag (`disallow-doctype-decl`) neutralises a flow. Examples flagged but
  marked SECURE by the author: Persistent XSS levels 8/9, XXE levels 3/4/5/7, LDAP levels 4/6.
- A naive sanitizer-name filter (escape|encode|sanitize...) cost 13 true finds to remove 1 false alarm. Rejected.
- NodeGoat nosql-injection missed: the flow goes through `allocationsDAO.getByUserIdAndThreshold(...)`, a method defined
  as `this.fn = ...` in a constructor; the JS frontend does not resolve that call, so the flow breaks. Kavach's own JS
  flow engine handles it (it was built against NodeGoat, so that 5/5 is not an unseen-app result).
- NodeGoat xss missed (template-level reflection, no JS sink).

## Honest caveats
- My first sink tables found 0 command/LDAP sinks and used all arguments of `query()`. I corrected both (resolved
  method names, first-argument-only) after seeing the numbers. The tables use generic JDK/Spring/JDBC APIs, not
  VulnerableApp class names, but they were adjusted after a first look at this target, so VulnerableApp is not a clean
  held-out measurement. A held-out Java check should be run on BenchmarkJava next.
- My first VulnerableApp labels were wrong twice (brace-form annotations; `@AttackVector` also appears on SECURE
  variants). Final rule: vulnerable = `@AttackVector` and not `variant=Variant.SECURE`; secure = `variant=Variant.SECURE`.
  135 vulnerable, 45 secure, 2 unmarked and ignored.
- Joern's launcher scripts break on paths containing spaces and need GNU `greadlink`. Workaround used: a space-free
  symlink and a shim in `exp/third_party/bin/`. A product integration would need a cleaner install location.
- "Fixed" is 0 for all of this: no patching was run.

## Files
`scripts/joern_taint.sc`, `scripts/joern_score.py`, `scripts/label_vulnerableapp.py`, `scripts/joern_inspect.sc`;
`labels/VulnerableApp.json`; `results/joern/*.taint.tsv` (flows), `*.score.json`, `*.baseline.tsv`, `cpg/` (graphs).

---

# Part 2: sources / sinks / sanitizers as mined data files (2026-10-06)

Idea tested: instead of hand-written Joern tables, mine the sources, sinks and sanitizers out of community Semgrep
*taint-mode* rules into per-language JSON data files (same idea as `config/js_knowledge.json`), and drive Joern from them.

## What was built (all in exp/, Kavach untouched)
- `scripts/mine_taint_rules.py`: parses `exp/third_party/semgrep-rules` taint rules (python 59, java 21, javascript+typescript 73)
  into specs `{kind: call|access|param|typed, name, recv, type, arg, framework, rule}` grouped by class (from the rule's CWE).
  Reads `metavariable-regex` for Spring annotation names, `@$APP.route` decorators, and `(HttpServletRequest $REQ)` typed sources.
  Drops wildcard junk. Output: `knowledge/{python,java,javascript}.json`, with provenance per spec.
- `scripts/joern_taint_data.sc`: the Joern taint script, driven only by those files (no hand-written tables).
- Miner coverage: python 691 patterns parsed / 84 skipped; java 114 / 72; javascript 861 / 82.
  Specs mined (sources / sinks / sanitizers): python 149 / 66 / 9; java 27 / 30 / 8; javascript 132 / 287 / 18.
  Sink classes with at least one spec: Python cmd, code, deserialization, sql, nosql, xss, ssrf(1); Java sql, path, ssrf, xss,
  ldap, xpath, cmd; JavaScript path, code, ssrf, cmd, xss, sql, redirect, ssti, xxe.

## Results on the same three targets

| Target | Kavach pattern scan | Joern + hand-written tables | **Joern + mined data files** |
|---|---|---|---|
| NodeGoat (5 taint-scope bugs) | 5 | 3 (12 flows, 6 unexplained) | 3 (eval, ssrf, redirect; 33 flows, 26 unexplained) |
| VAmPI (1 taint-scope bug: SQLi) | 0 | 1 (wide entry points) | 0 as mined; **1 with wide entry points** (5 flows, 4 unexplained) |
| VulnerableApp, vulnerable levels found (of 52) | 10 (19%) | 46 (88.5%) | 10 (19%) |
| VulnerableApp, secure levels flagged (of 32) | 6 (19%) | 19 (59%) | **2 (6%)** |
| VulnerableApp TPR - FPR | 0.005 | 0.291 | 0.130 |

VulnerableApp by class with mined data (tp / fn vulnerable; fp / tn secure): command 5/0, 1/0; ssrf 4/0, 1/0; sql 1/8, 0/12;
xss 0/24, 0/11; ldap 0/4, 0/2; xxe 0/3, 0/4; deserialization 0/2; code-injection 0/1.
"Unexplained" flows are flows not matching a labelled bug; not yet triaged by hand, so not all are false alarms.

## What it shows
- **Precision is the gain.** Mined data cut false alarms on safe levels from 59% to 6% (and below the pattern scan's 19%).
- **Recall is the loss, and it is a coverage problem in the community rules, not in the idea.** The gaps, per class:
  - SQL: community Java rules model string-building (`format`/`concat`/`append`) plus a few sinks (`Connection.prepareStatement`,
    `JdbcTemplate.batchUpdate`); Spring's `JdbcTemplate.query/queryForObject` is not a sink.
  - XSS: sinks are `HttpServletResponse.getWriter` and HTML-literal concatenation; Spring `ResponseEntity<String>` bodies are not covered.
  - LDAP: only `javax.naming.DirContext.search`; the UnboundID library is not modelled.
  - XXE: the community rules are "missing hardening flag" checks, not taint rules: no source/sink pair to mine.
  - Python has no mined sink for path traversal, redirect, SSRF (1 spec), XXE; VAmPI's path parameters need an entry-point model
    (OpenAPI/connexion routing has no decorator), which is why `wide=true` was needed.
- **Information is lost in the conversion.** Some rules constrain a sink with a regex on a string literal ("starts with SELECT");
  the data schema has no field for that, so those sinks become broader than the rule intended.
- Hand-written tables reached 88.5% only by treating all `query/execute/update` arguments as sinks; mined data is the opposite.

## Conclusion
Data files mined from community taint rules are a good, auditable **precision** layer and give the framework-aware
sources (Spring annotations, Flask decorators, Express request properties, servlet request types) for free, but alone
they do not give recall. The practical design is a union: community-mined specs as the base, plus a curated or
LLM-proposed (IRIS-style, flagged `candidate`) addition for libraries the community rules do not model (JdbcTemplate query
methods, Spring response bodies, UnboundID LDAP), written back into the same data file like `learn` does for JS today.

## Caveats
- I stopped editing the miner after the first full run: tuning it further against VulnerableApp would be overfitting.
  Two generic miner fixes (Spring annotation names via `metavariable-regex`, typed sources) were made after seeing empty
  source lists, before the final run; VulnerableApp is therefore not a clean held-out test for the miner either.
- The scorer attributes a flow to the request-handler method that holds the source; VulnerableApp results use that rule.
- Semgrep Rules License v1.0 applies to the mined data; check before shipping `knowledge/*.json`.
- "Fixed" is 0: no patching was run.

---

# Part 3: hybrid = mined data + LLM-proposed gap specs (2026-10-06)

Model: `nvidia.nemotron-nano-3-30b` through the OpenAI-compatible endpoint the user supplied (key passed via environment only;
not written to any file; `grep` of exp/ and the memory folder finds none). 49 calls, 55k tokens in, 30k out, 204 s, 0 errors.

## Method (IRIS-style spec inference)
1. `scripts/joern_candidates.sc`: list the distinct library/external API calls each app uses (calls into the app's own types are
   dropped deterministically, so the model never sees app-internal code paths). 64 / 104 / 290 distinct APIs for VAmPI / NodeGoat / VulnerableApp.
2. `scripts/llm_spec_infer.py`: the model sees only the API name plus one short usage line and must return strict JSON
   (role source|sink|sanitizer|none, class, argument index). Unknown ids, roles, classes or arguments are discarded (0 malformed, 7 invalid in a first, unfiltered run).
   Accepted specs are tagged `classified_by: llm` and anchored to the exact resolved API name. Every call is logged to `results/llm_trace.jsonl`.
3. `scripts/merge_knowledge.py`: mined file + LLM specs = hybrid file (`knowledge/hybrid_*.json`); `--pool` shares request-input sources
   (annotated parameters, typed request objects, request property access) across classes (`knowledge/hybridpool_*.json`).
4. Same Joern script and same scorer as before. Accepted LLM specs: VAmPI 17, NodeGoat 19, VulnerableApp 47.

## Results on the same three targets

| Target | Kavach pattern scan | Joern + hand-written tables | Joern + mined | **Hybrid** (mined + LLM) | **Hybrid, request sources pooled** |
|---|---|---|---|---|---|
| NodeGoat taint bugs found (of 5) | **5** | 3 | 3 | 3 | 3 |
| VAmPI SQLi found | 0 | 1 (wide) | 0 / 1 (wide) | 0 / 1 (wide) | 0 / 1 (wide) |
| VulnerableApp vulnerable levels found (of 52) | 10 (19%) | **46 (88.5%)** | 10 (19%) | 17 (33%) | 24 (46%) |
| VulnerableApp safe levels flagged (of 32) | 6 (19%) | 19 (59%) | **2 (6%)** | 4 (12.5%) | 7 (22%) |
| VulnerableApp TPR - FPR | 0.005 | 0.291 | 0.130 | 0.202 | **0.243** |
| Flows not matching a labelled bug (NodeGoat / VAmPI) | 6 / 1 | 6 / 1 | 26 / 4 | 29 / 19 | 35 / 22 |

VulnerableApp by class, hybrid pooled (tp / fn on vulnerable; fp / tn on secure): sql 8/1, 2/10; command 5/0, 1/0; ssrf 4/0, 1/0;
ldap 4/0, 2/0; deserialization 2/0, 1/0; code 1/0; xxe 0/3, 0/4; xss 0/24, 0/11.

## What it shows
- **The LLM filled real gaps.** SQL went from 1 to 8 found once it proposed `JdbcTemplate.query/execute` and `EntityManager.createQuery`
  as sinks; LDAP from 0 to 4 once request inputs were pooled (it proposed `LDAPConnection.search`, which the community rule omitted).
  Servlet `getParameter/getCookies/getHeader` and Spring `RestTemplate.getForObject`, `ObjectMapper.readValue` were also correct.
- **It also adds noise.** Examples of wrong proposals: `Cipher.doFinal` and `BCryptPasswordEncoder.encode` as code-injection sinks,
  `Filter.encodeValue` (a sanitizer) as an LDAP sink, `SAXParserFactory.setFeature` (XXE hardening) as an XXE *sanitizer* of the right kind but off the data path,
  `ResultSet.getInt` as an SQL sink, getters as sources. In the JS and Python apps most flows are unmatched (NodeGoat 35, VAmPI 22),
  mainly app-internal DAO/model calls the model cannot tell apart from library calls (no package name to filter on).
- **Trade-off, now measured:** mined only = best precision (FPR 6%), hybrid pooled = best balance of the data-file approaches (0.243),
  hand-written tables = best recall (88.5%) with the worst precision (FPR 59%). No variant reaches the 5 of 5 that Kavach's own
  NodeGoat-built JS engine gets on NodeGoat.
- **Still missing for every data-file variant:** XSS (0 of 24: Spring `ResponseEntity<String>` bodies are not modelled as sinks by the
  community rules, and the model labelled `BodyBuilder.body` as an SQL sink), XXE (community rules are hardening checks, not taint rules),
  and NodeGoat NoSQL (the DAO call is not resolved by the JS front end).
- Pooling request sources was a design change I made after seeing the LDAP result; the numbers for that column are therefore not a
  clean pre-registered test.

## Caveats
- VulnerableApp is not held out: the miner, the sink tables and now the pooling were all adjusted after looking at it. BenchmarkJava (or another unseen
  Java app) is the clean test, and the LLM specs should be generated there from scratch.
- One LLM, one run, temperature 0; not repeated, so run-to-run variation is unmeasured.
- Joern gets the LLM's verdict only through the data file; the LLM never decides whether a flow is a bug, and nothing here was exploit-confirmed. "Fixed" is 0.
