# OWASP BenchmarkJava: held-out run of the new pipeline (2026-10-07)

BenchmarkJava v1.2: 2,740 servlet test cases, 1,415 real vulnerabilities and 1,325 safe look-alikes across 11 categories. Static analysis only (the live checks need the app deployed; not run here).
Scoring is the standard OWASP method: per category TPR (real vulns found), FPR (safe tests flagged), TPR-FPR (Youden). A test counts as flagged for a category if a finding of
that category lies in that test's file (a finding in a shared helper is attributed to the test file that supplied the source). Nothing was fixed or patched; nothing was pushed.

## Held-out discipline
- The pipeline is the one from `STEPS_1_5_RESULTS.md` / `LAMBDA_FIX.md`, run once, no tuning on these labels. One generic addition was made before running: `@WebServlet` routes in the route extractor (framework knowledge; the route *path* encodes the category in this benchmark and is not used by any detector, only the `(file, function)` entry points are).
- The LLM specs were generated from scratch on this app (`llm_spec_infer.py`, nvidia.nemotron-nano-3-30b, 11 calls, 264 candidate APIs, 50 accepted specs, 0 failed batches). The model sees API names and short usage lines only, no comments, no labels.
- Misuse catalogue, framework checks, mined community data: unchanged from before.
- Cost and time on this Mac: code graph 67 s, taint run about 2 minutes, misuse run about a minute, 11 LLM calls.
- Caveat: the project as a whole was developed while looking at VulnerableApp, VAmPI and NodeGoat, never at BenchmarkJava, so this is as held-out as I can make it.

## Results (all 2,740 tests)

| variant | TPR | FPR | TPR - FPR |
|---|---|---|---|
| K Kavach pattern scan (before) | 0.205 | 0.194 | 0.011 |
| C community Semgrep java rules | 0.882 | 0.417 | **0.465** |
| T taint, steps 1-4 (Joern + mined/LLM data) | 0.571 | 0.540 | 0.031 |
| M misuse catalogue (step 3) | 0.309 | 0.020 | 0.288 |
| **N = T + M (the new pipeline)** | **0.880** | **0.561** | **0.319** |
| N + C | 0.943 | 0.590 | 0.353 |
| N + K + C | 0.943 | 0.598 | 0.346 |

Per category, new pipeline N (real, found, safe, flagged, TPR, FPR, TPR-FPR):

| category | real | found | safe | flagged | TPR | FPR | TPR-FPR |
|---|---|---|---|---|---|---|---|
| weak random | 218 | 218 | 275 | 0 | 1.00 | 0.00 | **1.00** |
| hash | 129 | 89 | 107 | 0 | 0.69 | 0.00 | 0.69 |
| crypto | 130 | 130 | 116 | 27 | 1.00 | 0.23 | 0.77 |
| SQL injection | 272 | 261 | 232 | 205 | 0.96 | 0.88 | 0.08 |
| command injection | 126 | 126 | 125 | 121 | 1.00 | 0.97 | 0.03 |
| path traversal | 133 | 133 | 135 | 131 | 1.00 | 0.97 | 0.03 |
| LDAP injection | 27 | 27 | 32 | 30 | 1.00 | 0.94 | 0.06 |
| XPath injection | 15 | 15 | 20 | 20 | 1.00 | 1.00 | 0.00 |
| XSS | 246 | 246 | 209 | 209 | 1.00 | 1.00 | 0.00 |
| secure cookie | 36 | 0 | 31 | 0 | 0.00 | 0.00 | 0.00 |
| trust boundary | 83 | 0 | 43 | 0 | 0.00 | 0.00 | 0.00 |

## What it shows
- Against the original Kavach pattern scan this is a large gain (0.011 -> 0.319), and TPR rises from 0.205 to 0.880.
- **On this benchmark it does not beat the plain community Semgrep rules** (0.319 vs 0.465): the community rules have far fewer false alarms on the taint categories (for example XSS 0.52 vs 1.00, SQLi 0.73 vs 0.88) and also catch secure-cookie and trust-boundary cases that we do not. The union N + C (0.353) is lower than C alone because the taint layer adds false alarms without adding discrimination.
- **The misuse catalogue is the strong part**: weak random 1.00/0.00, hash 0.69/0.00, crypto 1.00/0.23, with a 2% overall false-alarm rate.
- **The taint layer does not discriminate**: it flags 88-100% of the safe tests in every taint category, so it is effectively a "this servlet reads a request value and calls a sink" detector.

## Why (verified in the source, no retuning done)
1. **Dead branches and constants are not folded.** Safe command-injection test `BenchmarkTest00090` computes `if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;` with `num = 86`, so `bar` is always the constant, but the graph taints both branches. The benchmark's safe cases are built from this kind of trick (constant conditions, `switch` on a constant, a list from which the tainted element is removed, a helper that returns a constant).
2. **Algorithm names come from a properties file.** `BenchmarkTest00003` (a real hash case) does `benchmarkprops.getProperty("hashAlg1", "SHA512")`; the catalogue sees only the default literal, so 40 real hash tests are missed. `BenchmarkTest00059` (safe) does `getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding")`, and the catalogue wrongly flags the default literal: this is the source of the 27 crypto false alarms.
3. **The cookie check is not value-aware.** It asks whether `setSecure` is absent; the benchmark's vulnerable cookies call `setSecure(false)` and its decoys call `setSecure(true)`, so the check never fires (0 of 36).
4. **There is no trust-boundary class** (a tainted value stored with `session.setAttribute`), so 0 of 83.
5. Request sources are pooled across classes (typed `HttpServletRequest` parameters and `getParameter`/`getCookies`), so every test's request reaches every sink class.

## What this says about next steps
Four generic, deterministic features would address exactly these causes: constant folding with dead-branch pruning, resolution of `Properties.getProperty(key, default)` against the repository's `.properties` files, value-aware setter checks (`setSecure(false)`, `setHttpOnly(false)`), and a trust-boundary class. Implementing them now would make BenchmarkJava no longer held out, so they should be evaluated on a second unseen benchmark (Juliet Java is downloaded in `benchmark_workspace/public/juliet-java`).

## Caveats
- One run of one configuration; LLM specs from one model at temperature 0, not repeated.
- The taint step runs with the `second` and `bind` options on, as in the final configuration; neither contributed on this app (0 bound edges; second-order keys: `users` only).
- Misuse "VIA" rows (callers of a tagged helper) are included in N.
- K and C numbers are from the earlier baseline and community-rule runs (`results/BenchmarkJava.findings.json`, `results/community/`).
- The scorer attributes by test file, so a category flag from any finding in that file counts, as in the earlier baseline scoring.
- Files: `scripts/bj_score.py`, `results/bj_final.json`, `results/joern/BenchmarkJava.final4.tsv` (taint rows), `results/joern/BenchmarkJava.misuse.tsv`, `knowledge/llm_BenchmarkJava.json`, `knowledge/hybridpool_BenchmarkJava.json`.
