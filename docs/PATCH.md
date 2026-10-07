# AI Kavach — Patching (the FIX stage)

Patching is **template-first and deterministic**. The cheap, well-understood classes are fixed by a fixed
mechanical edit — no model, no variance; the config classes get an exact framework-aware remediation; and an
LLM is used **only** where a real code rewrite is unavoidable, always behind the verification gate
(`docs/VERIFY.md`). Dependency vulnerabilities are reported, never version-bumped.

## 1. By the numbers

| Asset | Count |
|---|---|
| FIX tiers | **3** (template → config-remediation → gated LLM) |
| Deterministic template rules / classes | **6 rules / 4 classes** |
| Config-remediation classes × frameworks | **9 × 5** |
| Code-repair backends (LLM, gated) | **3** (Python, Java, JavaScript) |
| Verification-gate stages before a patch is accepted | **4** (see §5 / `docs/VERIFY.md`) |
| Dependency classes auto-refused (advisory-only) | **5** |
| LLM variance on the template/config tiers | **0** |

## 2. Tier 1 — deterministic templates (`src/autonomy/template_patch.py`)

Pure literal swaps, applied on a scratch copy, re-verified (the weak literal is gone), and **line-scoped** so
a fix can never falsely claim a sibling site. **6 rules across 4 classes:**

| class | rewrite | langs |
|---|---|---|
| weak-hash | `getInstance("MD5"/"SHA-1")` → `"SHA-256"`; `hashlib.md5/sha1(` → `hashlib.sha256(` | Java, Python |
| weak-random | `new Random()` → `new java.security.SecureRandom()` (no-arg; SecureRandom extends Random) | Java |
| cookie-flags | `setSecure(false)` → `setSecure(true)`; `setHttpOnly(false)` → `setHttpOnly(true)` | Java |
| cookie-samesite | `setHttpOnly(false)` → `setHttpOnly(true)` | Java |

These cannot change behaviour beyond the security property and always compile — re-scan is the whole gate.
Zero model cost, zero variance. (Measured: 64/64 such literals patched + verified on held-out BenchmarkJava.)

## 3. Tier 2 — framework-aware config remediation (`src/autonomy/config_fixes.py`)

The classes we confirm over HTTP but that have **no code sink to splice** (clickjacking, cookie-flags,
cookie-samesite, CORS, CSRF, rate-limit, JWT none/weak-secret/no-expiry — **9 classes**) get the exact fix
snippet for the target's framework, detected from the tree (**express / spring / flask / django / rails**,
with a generic HTTP fallback), plus how to verify (re-run the live oracle). RoE explicitly permits config
fixes. Placement is app-specific, so these are precise, ready-to-apply remediations attached to the finding.

Example (express, detected): clickjacking → `app.use(require('helmet').frameguard({action:'deny'}))`;
no-rate-limit → `app.use('/login', require('express-rate-limit')({windowMs:60000, max:5}))`;
csrf-missing → `app.use(require('csurf')())`.

## 4. Tier 3 — gated LLM repair (CEGIS), only where a code rewrite is needed

For a confirmed **code-location** finding with no safe template (SQLi→parameterized, XSS→escaper,
command-injection, logic), the matching backend repair loop runs (`src/{pyauto,javaauto,jsauto}/repair.py` —
**3 backends**). It rewrites exactly one function, splices it by AST byte-range (tree-sitter), and the patch
must pass the full verification gate (§5). If the gate rejects, the **concrete failing counterexample** (the
attacking request, or the still-present data-flow) is fed back to the model for the next attempt — this is
counterexample-guided repair (CEGIS), not a vague retry. Requires `--url` + a local model
(`OPENAI_BASE_URL`); Python/JS also need `--run-cmd` to start the patched app for the gate.

## 5. The verification gate (summary; full detail in `docs/VERIFY.md`)

A patch is accepted only if **all four** hold:
1. **PoV-gone** — the confirming exploit no longer fires on the patched build;
2. **Regression** — recorded good traffic still returns identical responses (behaviour preserved);
3. **Static re-scan** — the taint scanner finds the vuln *class* gone from the patched file (not just the one
   input); otherwise the patch is rejected and the still-present flow is the counterexample;
4. (after acceptance) **sibling-sink review** — the same class is re-scanned at other files and any twin is
   surfaced as a candidate.

Gate stages observed in the loop: `start → pov → regression → rescan → accepted`. Java builds `--offline`
(incremental daemon, no network dependency on an offline host).

## 6. Dependency policy — advisory, never bump

**5** dependency class names (`vulnerable-dependency, dependency, sca, cve, known-vulnerable-dependency`) are
hard-refused by the patch engine: we name the fixed version but never edit a manifest or bump a version.
Rationale: an offline target cannot re-resolve/reinstall/test, and a version change can break the app. This
matches the advisory-only behaviour in the per-backend dependency handling.

## 7. Why template-first

- **Speed**: templates are instant; config snippets are generated, not searched; the slow model path is used
  only when a real rewrite is needed.
- **Correctness & zero variance**: a literal swap is provably the fix for its class and can't hallucinate; the
  LLM tier is always gated by a replayed exploit + behaviour preservation + a class-level re-scan.
- **Coverage**: the three tiers close find→prove→**fix** for the common literal classes, the confirmed config
  classes (our highest-confidence findings), and the code-sink injection classes — across Python, Java and
  JavaScript.

See `docs/ARCHITECTURE.md` (pipeline), `docs/PROVE.md` (confirmation), `docs/VERIFY.md` (the gate & proof).
