# Steps 1-5 on NodeGoat, VAmPI and VulnerableApp (2026-10-07)

Everything is in `exp/`. Nothing in `src/` or `config/` was changed. Nothing was pushed. Detection steps 1-4 are deterministic (no LLM at run time);
step 5 is deterministic HTTP checks against a running copy of each app. The only LLM use is the earlier spec inference (`llm_spec_infer.py`, 49 calls).

## What was built

| Step | Files | What it does |
|---|---|---|
| 1 Route map as entry points | `scripts/route_map.py`, `knowledge/routes_*.json` | Extracts routes from OpenAPI/connexion (operationId -> function), Spring (any `*Mapping` on a `*Controller`, constants resolved), Express (verb + path + middleware chain + handler), Flask decorators. The handler parameters become taint sources (`routes=` in `joern_taint_data.sc`). |
| 2 Framework checkers as data | `knowledge/framework_checks.json`, `fwSinks` in `joern_taint_data.sc` | Kinds: returned-body sink (string-returning handlers), response with 3xx status, header write to `Location` (header name resolved through constants), config-gated sink (render is an HTML sink only when autoescape is off), HTML-literal string build. |
| 3 Misuse catalogue + constants + call-graph tags | `knowledge/misuse_catalog.json`, `scripts/joern_misuse.sc`, `scripts/misuse_score.py` | Weak hash/cipher/random, JWT none / unverified / hardcoded key, cookie flags, risky headers, CSRF disabled, TLS verify off, debug, hardcoded secrets, session config, missing CSRF middleware. Arguments are resolved through literals and static-final fields; weak-primitive names (e.g. an enum constant `MD5`) tag a method, and its callers (depth 3) inherit the tag. Comments are stripped before matching. |
| 4 Second-order store -> load | `knowledge/second_order.json`, `second` block in `joern_taint_data.sc` | Tainted writes to a store (repository / SQL table / collection) make reads of the same key sources. |
| 5 Live deterministic checks | `scripts/live_checks.py`, `scripts/live_run.py` | Loopback-only, capped, sequential oracles: framing headers, cookie flags, CORS, host-header reflection, login rate limit, username enumeration, session-token entropy, JWT (alg none, weak HS256 secret by short wordlist), CSRF token in forms (absent or empty), sensitive fields, and marker oracles for open redirect, reflected XSS, header injection. |
| Report | `scripts/final_report.py`, `results/final_matrix.json` | One scorer over all detectors and steps. |

Setup that was needed to run the apps (all inside `exp/`): JDK 17 (Temurin) + Gradle cache for VulnerableApp (Spring Boot 2.7), a Python venv for VAmPI, the project's own loopback `AppServer` + local MongoDB for NodeGoat.
Packages added to the conda env are logged in `INSTALLED.md` (`tree-sitter-python`, `tree-sitter-java`, `pyyaml`).

## Results

### VulnerableApp: taint-class levels (75 vulnerable, 38 secure), Joern + mined/LLM data
| | found of 75 | secure flagged of 38 |
|---|---|---|
| before steps (hybrid, pooled sources) | 30 | 8 |
| + step 1 route-map entry points | 30 | 8 |
| + step 2 framework checks (body / redirect / header) | 42 | 11 |
| + step 2 HTML-literal string-build sink | **48** | **14** |
| + step 4 second-order | 48 | 14 (no change) |

Ablation: running the framework checks without step 4 gives exactly 48 / 14, so **step 4 contributed nothing** on this app. Of the 23 vulnerable XSS levels in this taint scope, found went 0 -> 9 -> 15.

### VulnerableApp: all bug types, per (level, type) instance (143 instances in types any detector can address; 20 secure instances)
| | found | secure flagged |
|---|---|---|
| Kavach pattern scan (K) | 10 | 5 |
| prior best taint (hybrid pooled) | 30 | 5 |
| K or prior taint | 32 (22%) | 9 of 20 |
| **steps 1-5 together** (taint + misuse + live) | **75 (52%)** | **7 of 20** |
| steps 1-5 plus K | 77 (54%) | 11 of 20 |

By step: taint after steps 1/2/4 = 50 instances; misuse catalogue (step 3) = 21 (weak hash 8, JWT 9, weak random 2, weak cipher 1, framing header 1); live (step 5) = 13 of which only 4 are new (clickjacking +2, rate limit +1, JWT +1, the rest repeat XSS the taint pass already found). Misuse and live flagged 0 secure instances (only 1 secure instance is in scope for misuse, so that false-alarm figure is weak).

Fully found: command injection 5/5, SSRF 4/4, LDAP 4/4, deserialization 3/3, blind/union SQLi 4/4, weak password hash 5/5.
Partly found: reflected XSS 10/18, persistent XSS 8/13, path traversal 6/15, open redirect 2/9, SQLi (error-based) 4/5, JWT 10/19, weak hash 3/5, weak random 2/3, clickjacking 3/5, weak cipher 1/3, rate limit 1/6.
Not found by steps 1-5: XXE 0/3 (K finds 2), cache poisoning 0/4, insecure JWT configuration 0/3, username enumeration 0/2, insecure crypto storage 0/2, predictable reset token 0/2, predictable session id 0/2, header injection 0/1, remote code execution 0/1.

### NodeGoat (12 labels)
| | found |
|---|---|
| Kavach pattern scan (built on this app) | 12 |
| steps 1-5 | 7: eval, ssrf, open redirect and NoSQL injection (taint; NoSQL added by the 2026-10-07 callback/instance-resolution fix, see `LAMBDA_FIX.md`); hardcoded cookie secret, insecure session config (step 3); missing CSRF (steps 3 and 5; the form has a `_csrf` field but it is rendered empty) |
| project's existing authenticated live probes, re-run today | 7 of 7 in scope (nosql, eval, xss, ssrf, redirect, idor x2), 6.8 s |
| steps 1-5 + project live probes | 10 of 12 (not found: private key file, ReDoS (excluded by the rules of engagement)); the NoSQL fix does not change this union, the live probes already had it |

Steps 1-5 miss on NodeGoat: XSS (cause not established; the chain goes through database writes and a render call), IDOR x2, private key file, ReDoS. (NoSQL was missed originally because the front end linked the DAO call only to an external placeholder; fixed, see `LAMBDA_FIX.md`.)

### VAmPI (10 labels)
| | found |
|---|---|
| Kavach pattern scan (labels as matched here) | 0 |
| steps 1-5 | 5: SQL injection (from the route-map entry points, no "all parameters" hack), data exposure, user enumeration, missing rate limit, weak JWT secret |
| project's existing authenticated live probes, re-run today | 7 of 7 in scope (SQLi, BOLA x3, mass assignment, data exposure, enumeration), 16.5 s |
| steps 1-5 + project live probes | 9 of 10 (not found: ReDoS, excluded by the rules of engagement) |

BOLA x3 and mass assignment need two authenticated users and state; the generic checker does not do them (the project's probes do).

## What did and did not work
- **Step 1** removed the need for the "wide entry points" hack on VAmPI (5 handler parameters as sources, 26 flows instead of 34). No effect on the other two apps.
- **Step 2** was the largest static gain (+18 found on VulnerableApp), at the cost of 6 more secure levels flagged. The HTML-string sink is the single most productive check and also the broadest.
- **Step 3** found the weak-hash, JWT and weak-random levels that no pattern or taint rule had found, with zero false alarms on the one secure instance in scope, and found NodeGoat's secret, session and CSRF labels and VAmPI's hardcoded JWT key. It also produced one false hit (a `Password` dictionary key in VAmPI).
- **Step 4** did not help. The machinery works (it identified `PostRepository` as a tainted store and produced second-order flows through it), but on VulnerableApp the dedicated persistent-XSS levels were already flagged first-order, because the engine's default handling of external calls treats a repository as tainted once tainted data is saved into it. **Correction (2026-10-07):** an earlier version of this paragraph blamed a lambda that mutates a captured variable; that was wrong for this app. The closure blind spot is real and is now fixed (see `LAMBDA_FIX.md`: micro-benchmarks Java 8 to 12 of 13, JS 5 to 10 of 10), and it unlocked one verified NodeGoat finding, but it changed no VulnerableApp score.
- **Step 5** confirmed VAmPI and NodeGoat findings that static analysis cannot reach and added 4 VulnerableApp instances. It could not exercise the session, enumeration and cache-poisoning levels: they need valid credentials or multi-step flows that single-request oracles do not have.

## Caveats
- Not held out: all three apps influenced the framework checks (response-entity redirect, HTML-literal string build), catalogue entries (enum tokens) and live checks. BenchmarkJava or another unseen app is the clean test.
- VulnerableApp ground truth is the author's annotations (`@AttackVector` and `variant = SECURE`). The app's own answer-key endpoint (`/scanner/dast`) was not used for any detection; I only requested my route map's URLs to check reachability (196 of 215 reachable, 2 not found).
- The live checker was given VAmPI's seeded test user (`name1` / `pass1`), as a deployment with test credentials would. Without credentials the VAmPI JWT secret is not found.
- Clickjacking is judged by the standard policy (no header, `ALLOWALL`, `ALLOW-FROM` or `frame-ancestors *` is weak; `SAMEORIGIN` is not), so the three `SAMEORIGIN`-style levels the author counts as vulnerable are not found. The live checker reports clickjacking on every route lacking the header (192 of 215), so on its own that class is noisy; it is only meaningful scored per label.
- There are only 20 secure instances in scope, so false-alarm percentages are coarse.
- The Kavach pattern scan's NodeGoat result is not an unseen-app result (it was built on this app).
- `final_report.py` counts (level, type) instances; a level with two types counts twice. The earlier per-level tables use a different unit.
- No patching or fixing was run, so "fixed" is 0 throughout.
