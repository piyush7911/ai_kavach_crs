# Gap analysis: what we miss on NodeGoat, VAmPI and VulnerableApp, why, and deterministic ways to close it (2026-10-06)

Written from the benchmark runs in this folder. K = Kavach pattern scan (unmodified), H = Joern + hand-written tables, M = Joern + mined data,
Y = hybrid (mined + LLM specs), P = hybrid with pooled request sources, L = live HTTP probes (project records in `reports/`, not re-run here).
Nothing was fixed or patched. Nothing was pushed.

## Correction first
My earlier VulnerableApp scorer left out PATH_TRAVERSAL (15 vulnerable levels) and OPEN_REDIRECT (9), which are taint classes. Scope grows from 52 to 75
vulnerable levels in taint scope (38 secure levels). Corrected figures (found of 75 / secure levels flagged of 38):
K 10 (13%) / 6 (16%); H 46 (61%) / 22 (58%); M 10 (13%) / 3 (8%); Y 23 (31%) / 5 (13%); P 30 (40%) / 8 (21%).
The earlier "88.5%" for H and "46% / 24 of 52" for P were overstated; the ranking is unchanged (H best recall, M best precision, P best balance:
TPR-FPR 0.034 / 0.054 / 0.175 / 0.189 for H / M / Y / P; K -0.025).

## Where the gap comes from, at a glance
- With a live endpoint, the project's own probes found every in-scope bug on NodeGoat and VAmPI (7 of 7 each; NodeGoat is the app they were built against).
  The lag is in the source-only paths (pattern scan, Joern taint, data files).
- VulnerableApp: of 168 vulnerable (level, bug-type) instances, 55 are found by any static variant (55 of 84 taint-class instances, 0 of 84 non-taint instances).

## NodeGoat (12 labels)
| label | kind | K pattern scan | any Joern variant | live probes |
|---|---|---|---|---|
| nosql | dynamic | yes | no | yes |
| eval | dynamic | yes | yes | yes |
| xss | dynamic | yes | no | yes |
| ssrf | dynamic | yes | yes | yes |
| open-redirect | dynamic | yes | yes | yes |
| idor-alloc | dynamic | yes | no | yes |
| idor-benefits | dynamic | yes | no | yes |
| hardcoded-secret | static | yes | no | no |
| private-key | static | yes | no | no |
| session-cookie | static | yes | no | no |
| csrf | static | yes | no | no |
| redos | roe_excluded | yes | no | no |

Joern variants miss: nosql (the DAO call `allocationsDAO.getByUserIdAndThreshold`, defined as `this.fn = ...` in a constructor, is not resolved by the JS front end, so the flow breaks);
xss (reflection happens in a template, no JS sink); IDOR x2, hardcoded secret, private key, session cookie, CSRF and ReDoS are not source-to-sink flows at all.
K catches all 12 because the JS engine and rules were developed on this app (not an unseen-app result).

## VAmPI (10 labels)
| label | kind | K pattern scan | Joern | live probes |
|---|---|---|---|---|
| sqli | dynamic | no | yes (wide entry points) | yes |
| bola-password | dynamic | no | no | yes |
| bola-email | dynamic | no | no | yes |
| bola-books | dynamic | no | no | yes |
| mass-assign | dynamic | no | no | yes |
| data-exposure | dynamic | no | no | yes |
| enumeration | dynamic | no | no | yes |
| regexdos | roe_excluded | no | no | no |
| rate-limit | roe_excluded | no | no | yes |
| weak-jwt | static | yes | no | no |

Static/Joern find only the SQLi (needs the wide entry-point setting: VAmPI routes through an OpenAPI file with no decorators, so there is no `request.args` source) and the
hard-coded signing key. Everything else is a logic bug (BOLA x3, mass assignment, data exposure, user enumeration, rate limit), which static flow analysis cannot express; the live probes find them.

## VulnerableApp (182 level methods: 135 vulnerable, 45 secure, 2 unmarked)
Taint-class bug types: vulnerable levels | found by K / H / M / Y / P | found by any
| type | levels | K | H | M | Y | P | any |
|---|---|---|---|---|---|---|---|
| REFLECTED_XSS | 18 | 0 | 13 | 0 | 0 | 0 | 13 |
| PATH_TRAVERSAL | 15 | 0 | 0 | 0 | 6 | 6 | 6 |
| PERSISTENT_XSS | 13 | 0 | 8 | 0 | 0 | 0 | 8 |
| OPEN_REDIRECT_3XX_STATUS_CODE | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| ERROR_BASED_SQL_INJECTION | 5 | 4 | 5 | 1 | 4 | 4 | 5 |
| COMMAND_INJECTION | 5 | 0 | 5 | 5 | 5 | 5 | 5 |
| LDAP_INJECTION | 4 | 0 | 4 | 0 | 0 | 4 | 4 |
| SIMPLE_SSRF | 4 | 0 | 4 | 4 | 4 | 4 | 4 |
| INSECURE_DESERIALIZATION | 3 | 0 | 3 | 0 | 0 | 3 | 3 |
| XXE | 3 | 2 | 2 | 0 | 0 | 0 | 3 |
| BLIND_SQL_INJECTION | 2 | 2 | 2 | 0 | 2 | 2 | 2 |
| UNION_BASED_SQL_INJECTION | 2 | 2 | 2 | 0 | 2 | 2 | 2 |
| REMOTE_CODE_EXECUTION | 1 | 0 | 0 | 0 | 0 | 0 | 0 |

Non-taint bug types, found by none of the static variants (0 of 84): CLIENT_SIDE_VULNERABLE_JWT (10), UNRESTRICTED_FILE_UPLOAD (7), SERVER_SIDE_VULNERABLE_JWT (6), NO_LOGIN_RATE_LIMITING (6), WEAK_PASSWORD_HASHING (5), CLICKJACKING (5), WEAK_CRYPTOGRAPHIC_HASH (5), WEB_CACHE_POISONING (4), INSECURE_DIRECT_OBJECT_REFERENCE (4), USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM (3), INSECURE_CONFIGURATION_JWT (3), PASSWORD_RESET_TOKEN_WITHOUT_EXPIRY (3), WEAK_RANDOM_NUMBER_GENERATION (3), USERNAME_ENUMERATION (2), PLAINTEXT_PASSWORD_STORAGE (2), INSECURE_CRYPTOGRAPHIC_STORAGE (2), REUSABLE_PASSWORD_RESET_TOKEN (2), PREDICTABLE_PASSWORD_RESET_TOKEN (2), IMPROPER_AUTHORIZATION (1), DENIAL_OF_SERVICE (1), UNCONTROLLED_RESOURCE_CONSUMPTION (1), HEADER_INJECTION (1), PASSWORD_RESET_TOKEN_EXPOSED_VIA_REFERRER (1), INSECURE_PASSWORD_RESET_LINK (1), MISSING_LOGOUT_INVALIDATION (1), OBSCURED_PREDICTABLE_SESSION_ID (1), PREDICTABLE_SESSION_ID (1), SESSION_FIXATION (1).
A separate run of every community Java rule (pattern rules included: 48 findings, 12 distinct rules) put no finding inside any non-taint level either:
it fires on `AES/ECB` in a helper (`EncryptionUtils`), 3 cookies missing HttpOnly and 9 `@RequestMapping` without a method, but the level code
calls `MessageDigest.getInstance(hashAlgorithm.label(), "BC")` (algorithm via an enum, not a string literal), `new Random()` in `OTPService` and a JWT library the rules do not model.
(Attribution here is file/line based, so a rule firing in a helper that a level calls is not credited to the level; a call-graph attribution would be fairer.)

## Root causes (verified in the source unless marked likely)
1. **Missing library/framework specs.** Spring `ResponseEntity` bodies as XSS sinks, `JdbcTemplate.query`, UnboundID LDAP, response headers. Fixable with data, partly done by mining + LLM.
2. **Response-as-sink / framework return values.** Open redirect (9 levels, 0 found by any variant): the URL is added to a `Location` header on `new ResponseEntity<>(headers, HttpStatus.FOUND)`;
   there is no `sendRedirect` call to match. XSS: the sink is a returned body string.
3. **Indirection the taint engine loses.** Path traversal: the value travels `Map.get` -> `Supplier` lambda -> helper `readFile` -> `getResourceAsStream(BASE + fileName)`; open redirect also goes through
   `MultiValueMap.get(KEY).add(url)` and a `Function` validator (likely: container/lambda semantics; not isolated by experiment).
4. **Second-order flows (likely).** Persistent XSS stores input via JPA/JdbcTemplate and renders it from a later query; taint tools do not follow data through a database (5 of 13 persistent levels missed by the best variant).
5. **Constant propagation.** Weak hash/crypto algorithm chosen through an enum or constant (`hashAlgorithm.label()`), so literal-matching rules never fire.
6. **Absence checks.** Clickjacking (no frame-ancestors/X-Frame-Options), missing rate limit, missing logout invalidation, missing authorization: nothing to match; needs a "should exist but does not" query.
7. **Logic bugs.** IDOR/BOLA, username enumeration, session fixation, predictable tokens, password-reset flaws, mass assignment.
8. **Entry points without decorators.** VAmPI's OpenAPI/connexion routing.

## Deterministic, language-agnostic ways to close each (from the research)
| gap | approach | evidence |
|---|---|---|
| 1 library specs | Sources/sinks/sanitizers/summaries as extensible YAML data, like CodeQL's models-as-data (`sourceModel`, `sinkModel`, `summaryModel`), Joern's custom data-flow semantics, and the multi-language YASA design (framework specs as configuration, one unified AST). We already have the data-file path (mined + LLM). | CodeQL docs; Joern docs; YASA (summary only) |
| 2 response-as-sink | Framework-specific checkers as data: treat controller return values / `ResponseEntity(headers, 3xx)` / `Location` header writes as redirect and XSS sinks (YASA's Spring checker treats controller methods as entry points and parameters as sources). | YASA |
| 3 indirection | Better semantics for container and lambda types in the CPG (Joern lets you define semantics for methods it does not model; unmodelled externals default to propagating all arguments to the return). Measure with a small micro-benchmark per indirection kind. | Joern docs; PLDI'25 SOAP paper |
| 4 second-order | Model the data store as an intermediate node: tag DB writes (`save`, INSERT, `put`) and DB reads (`find`, SELECT) by entity/table, so a write of tainted data to table T becomes a source at reads of T. Published static approaches exist for PHP (Dahse and Holz, USENIX Sec 2014; STaint, ASE 2025 with LLM assistance). | USENIX Sec'14; ASE'25 |
| 5 constants | Constant/enum propagation on the CPG before matching crypto API arguments; or typestate-style rules (CrySL/CogniCrypt does this for Java crypto APIs: method-call order plus data-flow constraints). | CrySL, ECOOP'18 |
| 6 absence | Structural queries on the route map and framework configuration (is there an auth/CSRF/header/rate-limit policy for this route?), plus a **live response-header check** (X-Frame-Options / CSP frame-ancestors, cookie flags, CORS, HSTS) which is trivial and deterministic over HTTP. | route/middleware approach in the access-control results |
| 7 logic bugs | Route-level auth coverage and "object id used without comparing to the current user" structural queries find the *shape*; confirmation is by a two-user HTTP replay (our existing BOLA/metamorphic oracles). Published guidance is consistent: deterministic analysis for structure, an LLM or oracle for whether it is a real flaw. | access-control results |
| 8 entry points | Import the OpenAPI spec or the framework route map as taint sources and as the live-probe route list (already done for VAmPI in the live path). | route-extraction tools; YASA |

## What I would do next (each measured the same way: true / found / confirmed / patched)
1. Route-map + OpenAPI import as entry points for Python and Java (closes VAmPI's SQLi without the "wide" hack and feeds the live probes).
2. Spring/Express framework checkers as data: response-body and redirect-header sinks (targets VulnerableApp XSS 24 and open redirect 9).
3. Constant/enum propagation + a small crypto/JWT/cookie/random API-misuse catalogue as data (targets the crypto, hash, random and JWT levels).
4. Second-order store/load tagging (targets persistent XSS).
5. Live deterministic checks for the non-flow classes (headers, rate limit, enumeration, session/token behaviour, forged JWT) using the existing oracle engine.
6. Held-out confirmation on BenchmarkJava, because VulnerableApp, VAmPI and NodeGoat have all influenced what I built.

## Sources
- Access control static analysis and its limits: https://snyk.io/blog/ai-coding-agents-broken-access-control/ , https://nhimg.org/articles/llm-idor-detection-still-fails-when-authorization-spans-files/
- CrySL / CogniCrypt: https://arxiv.org/abs/1710.00564 , https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ECOOP.2018.10
- CodeQL models as data (Java): https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-java-and-kotlin/
- Joern custom data-flow semantics: https://docs.joern.io/dataflow-semantics/ ; language-agnostic taint (PLDI'25 SOAP): https://arxiv.org/abs/2506.06247
- YASA, multi-language taint on a unified AST: https://arxiv.org/pdf/2601.17390 (I only retrieved a short summary; no numbers are quoted from it)
- Second-order vulnerabilities: https://usenix.org/sec14/dahse , https://conf.researchr.org/details/ase-2025/ase-2025-nier-track/32/STaint-Detecting-Second-Order-Vulnerabilities-in-PHP-Applications-with-LLM-Assisted-
