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
