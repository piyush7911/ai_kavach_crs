# Template patching results (Phase 1 MVP, 2026-10-07)

Deterministic, no-LLM template patches for the pure literal-swap classes. Applied on SCRATCH COPIES
(targets never modified), each re-verified: the weak literal is gone from the patched source.

## BenchmarkJava (held-out)
| class | template | files matched | applied + verified-clean |
|---|---|---|---|
| weak-hash | `getInstance("MD5"/"SHA-1")` -> `"SHA-256"` | 28 | **28 (100%)** |
| cookie-flags | `setSecure(false)` -> `setSecure(true)` | 36 | **36 (100%)** |

64 patches, zero model cost, zero variance. These are exactly the classes the misuse catalogue detects at
0 FP, so find -> (prove) -> fix is now deterministic end to end for them.

Scope note: BenchmarkJava also has weak hashes chosen via `getProperty("hashAlg","MD5")` (algorithm from a
.properties default, not a direct `getInstance` literal); those are detected but not in the literal-swap
template set — they need constant/default resolution (Phase 2) or the LLM fallback.

## What is deliberately NOT patched
- **Dependencies / CVEs**: advisory-only. `apply_templates` hard-refuses the dependency class family — we
  name the fixed version, never edit a manifest or bump a version (air-gapped: can't re-resolve/test; a bump
  can break the app).
- **weak-cipher mode (ECB->GCM)**, **SQLi->parameterized**, **XSS->escaper**, **inserting a missing cookie
  flag**: not pure literal swaps (GCM needs an IV; the others need a real AST rewrite), so Phase 2 behind the
  build/oracle gate, with the LLM as fallback.

## Next
Phase 3: integrate template-first into `src/*auto/patch.py` (try a template; on no-template or failed
re-verify, fall through to `repair.py`'s LLM loop — now fed the failed gate's counterexample, CEGIS-style).
Self-check: `python -m exp.scripts.patch_templates --self-check`.

## Phase 2 decision (2026-10-07)
Added a 3rd **safe** template: `new Random()` -> `new java.security.SecureRandom()` (no-arg only; SecureRandom
extends Random, no import needed). Seeded `new Random(seed)` has no matching ctor -> LLM. template_repair is
now LINE-SCOPED so it only claims the finding's own site.

The three originally-named "Phase 2 templates" are deliberately NOT built as deterministic templates:
- **SQLi -> parameterized**, **XSS -> escaper**, **weak-cipher ECB -> GCM** all require a real AST rewrite
  that can break compilation or change behaviour (GCM needs an IV; parameterization reshapes the call). A
  brittle template here would violate the no-false-claim / no-breakage principle.
- Correct design: these go through the **LLM repair loop, now CEGIS-enhanced** (the failed-gate
  counterexample is fed back) and gated by the existing build + PoV + regression gates. Deterministic where
  safe (hash/cookie/random), LLM-with-counterexample where not — exactly the research's recommended split.

A gated best-effort SQLi template (measured success vs LLM on the same findings) can be built in exp if we
want the number; expectation from the literature is partial success with the gate catching the rest.

## Detection wired (2026-10-07)
`benchmarks/scanners/misuse.py` (`kavach --misuse`): FP-safe source scan for direct misuse literals
(weak hash/cipher/random, cookie flags). VulnerableApp: 6 found (4 weak-random, 2 weak-cipher); `--fix`
template-patches 2 deterministically (no-arg Random), the rest (seeded Random, cipher) -> LLM.
