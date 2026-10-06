# Plan: deterministic patching (template-first) — exp then integrate (2026-10-07)

Based on `RESEARCH_deterministic_patching.md`. Build in `exp/` first; integrate into `src/*auto/patch.py`
only once it works. Nothing here bumps a dependency version (see "Dependencies" below).

## Principle
`finding → safe template for this class?  yes → mechanical AST/literal edit → re-verify → gate`
`                                          no  → LLM patch WITH the failed-gate counterexample → gate`
Templates are deterministic (zero model, zero variance) for narrow, well-understood classes; the existing
`repair.py` Alpha/Beta/Gamma LLM loop stays as the fallback and safety net. A patch is only accepted if it
**re-verifies**: the detector no longer fires on the patched source AND (for live classes) the oracle no
longer confirms, AND the app still builds/responds. Same gate discipline as today — the template only
changes how the candidate patch is produced.

## Classes and their fixes (confirmed/0-FP classes first)
| class | fix (mechanical) | lang | verify |
|---|---|---|---|
| weak-hash | `getInstance("MD5"\|"SHA-1")` → `"SHA-256"`; py `hashlib.md5(`→`hashlib.sha256(` | Java, Py | literal gone on re-scan |
| weak-cipher | `"DES/..."`→`"AES/GCM/NoPadding"`; `.../ECB/...`→`.../GCM/...` | Java, Py | literal gone |
| cookie-flags | `setSecure(false)`→`(true)`, `setHttpOnly(false)`→`(true)` | Java | live check: Secure/HttpOnly present |
| sql-injection | string-built query → parameterized (PreparedStatement `?` / cursor param) | Java, Py | injection oracle no longer flips |
| xss | raw output → framework escaper (`StringEscapeUtils.escapeHtml4`, Jinja autoescape) | Java, Py | reflected-XSS oracle silent |

Phase 1 (this MVP): the three literal-swap classes (weak-hash, weak-cipher, cookie-flags) — pure, provable,
no behaviour change beyond the security property. Phase 2: SQLi/XSS (need real AST rewrite, more care).
Phase 3: integrate template-first into `patch.py`; feed the failed gate's counterexample into `repair.py`'s
LLM retries as structured data (CEGIS-style), not a vague "try again".

## Dependencies — REPORT ONLY, never version-bump (hard rule)
A vulnerable library/CVE finding is reported as advisory (the fixed version is named) but **no template or
LLM ever edits a manifest or bumps a version** — the air-gapped finale cannot re-resolve/reinstall/test, and
a version change can break the app. This matches the existing `_repair_dependency` advisory-only behaviour.
The template engine explicitly refuses any class in the dependency family.

## Verification (what makes a template patch "proven")
1. The patched source is produced on a SCRATCH COPY; the target is never modified in place.
2. Re-run the same detector on the patched file → the finding must be gone.
3. For live classes, re-run the oracle against a rebuilt/running patched app → must no longer confirm.
4. The app must still build (Java: bootJar) and respond (no regression) — the existing gate.
A template that fails any step is discarded and the class falls through to the LLM fallback.

## Measurement (exp)
On VulnerableApp + BenchmarkJava: for each in-scope finding, template success rate and re-scan-clean rate,
vs the current LLM-only patch on the same findings. Report true/found/confirmed/**patched**.

## Files (exp)
`scripts/patch_templates.py` (the engine + self-check), `PATCHING_RESULTS.md` (numbers). No `src/` change
until Phase 3.
