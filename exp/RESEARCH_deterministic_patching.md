# Research: deterministic patching + LLM (2026-10-07)

Question: can patching get more deterministic, not just detection? Yes — three proven techniques, summarized with what
they'd replace in Kavach's current LLM-only patch step.

## 1. Template-based repair (TBar, CARES, TemVUR)
Fix patterns mined from real commits, applied mechanically by AST match-and-replace, no LLM involved for common classes.
- **TBar** (Defects4J): with fault location known, templates alone fix 74/101 bugs — most general bugs don't need an LLM at all.
  https://arxiv.org/pdf/1903.08409
- **CARES / TemVUR**: SQLi and XSS in Java fixed by a fixed template (parameterized query, output encoding via Intercepting Filter), not generation. TemVUR fixes 66.7% more vulnerabilities *securely* than leading (LLM-based) techniques.
  https://www.scitepress.org/Papers/2020/93699

**Fit for Kavach:** our bug classes are narrow and well-known (SQLi, XSS, command injection, weak hash, hardcoded secret, missing `HttpOnly`/`Secure`). Each has one or two standard mechanical fixes:
- SQLi (string-built query) → convert to prepared statement / parameterized call.
- XSS (raw output) → wrap in the framework's own escaper (`StringEscapeUtils.escapeHtml4`, `ESAPI.encoder()`, Jinja autoescape on).
- Weak hash/cipher → swap algorithm name constant (MD5→SHA-256, DES→AES/GCM).
- Missing cookie flag → set the literal to `true`.
- Hardcoded secret → replace with `System.getenv("...")` / `process.env...` read.

These are **tree-sitter AST edits**, same mechanism `src/*auto/patch.py` already uses to splice a function — just templated instead of LLM-generated for this subset.

## 2. Semantic patches (Coccinelle)
A DSL that matches *structure*, not text/regex, and rewrites every matching instance across a codebase in one pass.
"Find once, fix everywhere" — used for 6,000+ real Linux kernel security fixes. https://kernel.org/doc/html/next/dev-tools/coccinelle.html

**Fit:** when the same vulnerable call shape recurs across many files (e.g. 20 servlets all building SQL the same way), one semantic-patch rule fixes all of them identically and provably — far cheaper and more consistent than 20 separate LLM calls, and it can't introduce per-instance LLM variance/hallucination.

## 3. LLM only where no safe template exists, verified by counterexample loop
Research direction (2025–26): LLM is not asked to invent a patch blind — it's given a narrowed synthesis target and a **counterexample from the failed verification**, in a loop, same shape as Kavach's existing gate-feedback loop.
- CEGIS-based repair (AAAI 2025): LLM + fault localization + counterexample-guided loop **significantly outperforms** both plain LLM prompting and symbolic APR tools, and produces *smaller* fixes. https://ojs.aaai.org/index.php/AAAI/article/view/32046
- GitHub Copilot Autofix (CodeQL + GPT-4 in production): >90% alert-type coverage, ~2/3 of suggestions need no manual edit — **but GitHub's own stated limitation is that LLM suggestions can be syntactically or semantically wrong**, which is exactly why they still gate on CodeQL re-scan before merge. https://thehackernews.com/2024/03/github-launches-ai-powered-autofix-tool.html

## Recommended architecture change
```
finding → is there a safe template for this class?
   yes → apply template (AST edit, deterministic) → gates (same as now)
   no  → LLM generates patch, WITH the specific failed gate's counterexample
         fed back each retry (not just "it failed", but *why*, as structured data)
         → gates (same as now)
```
This is additive to what exists (`repair.py`'s Alpha/Beta/Gamma loop and policy gate stay as the fallback and the safety net), not a replacement:
1. Templates handle the common, well-understood classes deterministically — higher success rate, zero model cost, zero variance, for exactly the classes BenchmarkJava showed we can resolve with certainty (weak hash/crypto/random already hit 0 FP as *detections*; the fix for each is a 1-line constant swap, not a generation task).
2. LLM is reserved for classes with no safe mechanical fix (business logic, IDOR ownership checks, auth flow changes) — where it already is today.
3. Gate failures feed back as a **counterexample** (the literal failing request/response or sanitizer output), not a vague "try again" — matches the CEGIS result showing this improves success rate and shrinks patches.

## Caveat
Not evaluated on our benchmarks yet — this is research, no code changed. Next step if you want it: pick 2–3 classes (hardcoded secret, weak hash, missing cookie flag) and build their templates first, since detection already proved 0-FP for these; measure patch success rate template vs. current LLM-only on the same findings.
