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
