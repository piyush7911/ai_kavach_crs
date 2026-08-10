# AI Kavach CRS — Benchmark & Evaluation Results

**Platform:** Darwin arm64 / Python 3.11.15
**Mode:** parallel multi-agent ensemble (Alpha + Beta + Gamma + Delta Critic)
**Models:** `gpt-4o-mini` for all agents
**Architecture:** [`architecture.md`](architecture.md)

> Every figure in this document was measured during execution. Quantities that
> could not be measured on this platform are listed in §7 rather than estimated.

---

## 1. Headline Results

| Suite | Targets | Passed all gates | Rate | PoV-proven | Survived hardening | Time |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Synthetic (comment-free) | 20 | 20 | **100%** | 10 / 10 | 18 / 18 | 405s |
| Project Vanguard-0 (nightmare suite) | 4 | 4 | **100%** | 4 / 4 | 4 / 4 | 100s |
| CVE-inspired synthetic extension | 2 | 2 | **100%** | 2 / 2 | 2 / 2 | 52s |
| NIST Juliet | 2 | 2 | **100%** | 2 / 2 | 2 / 2 | 22s |
| Real World (cJSON, 3,000+ lines) | 6 | 6 | **100%** | – | 6 / 6 | 162s |
| Fuzz Discovery (libFuzzer) | 3 | 3 | **100%** | 3 / 3 | 2 / 2 | 53s |
| **Total** | **37** | **37** | **100%** | **21 / 21** | **34 / 34** | **794s** |

**Cost: $0.0521** across all 37 targets.

### The three bars, in increasing strength

1. **Passed all gates (37/37)** — the patch applied cleanly, compiled under
   AddressSanitizer + UndefinedBehaviorSanitizer, and cleared every check
   configured for that target.
2. **PoV-proven (21/21)** — the exact input that crashed the original no longer
   does, replayed against the *rebuilt patched binary*. Sixteen targets have no
   reproducible runtime exploit on this platform (§3) and cannot earn this bar.
3. **Survived hardening (34/34)** — each patch was actively attacked and held (§2).

---

## 2. Patch Hardening

Passing a gate is not proof. Three cheap attacks defeat gate-only verification,
and each is what a model optimising for a green gate would naturally produce:

| Attack | Clears every gate? | Falsified by |
| :--- | :---: | :--- |
| **PoV overfitting** — special-case the crashing input (`if (size == 4) return;`) | yes | **Adversarial re-fuzzing** of the patched build, seeded with the original crash |
| **Functionality gutting** — disable the code path with an early `return` | yes | **Differential testing** against the original across generated benign inputs |
| **Incomplete validation** — a sanitiser a cleverer payload slips past | yes | **Evasion battery** — bypass encodings (`....//`, `sub/../../`, `.././`) replayed against the patched build |

Which check applies depends on the fix's behavioural contract:

- **`preserve`** (memory-safety fixes) — behaviour must match the original wherever
  the original did not crash: differential testing, plus re-fuzzing where a
  harness exists.
- **`restrict`** (input-validation fixes: injection, traversal, dimension checks) —
  the remediation *is* to reject inputs the original accepted, so behavioural
  equivalence is the wrong contract. Hardened by re-fuzzing where a crash is the
  failure mode, and by the evasion battery where it is not.

No check may pass vacuously. The evasion battery reports *inconclusive* if
legitimate access is broken, so a patch that rejects everything cannot score as
hardened; and `SURVIVED` requires that a falsification attempt actually ran.

---

## 3. Coverage of the PoV bar

Sixteen of 37 targets have no reproducible runtime exploit on this platform. Each
carries a written reason in its manifest, is reported `SKIPPED`, and is never
counted as PoV-proven:

| Target | CWE | Why no PoV exists on this platform |
| :--- | :--- | :--- |
| SYN-01 magic bytes | CWE-190 | The overflow path is unreachable from the entrypoint: the version field `0x0100` contains a NUL byte, so no argv string satisfies the header guards |
| SYN-08 path traversal | CWE-22 | The hardcoded base directory `/var/www/html/users` does not exist; creating it requires root |
| SYN-10 null deref | CWE-476 | The 800 KB allocation never fails, so the missing NULL check never manifests |
| SYN-13 TOCTOU | CWE-367 | Winning the race requires a concurrent attacker; not deterministic in-process |
| SYN-14 uninit read | CWE-457 | Requires MemorySanitizer (Linux-only); ASan does not model uninitialised memory |
| SYN-15 hardcoded key | CWE-321 | No runtime signature; statically observable only |
| SYN-17 memory leak | CWE-401 | Requires LeakSanitizer, unsupported on darwin-arm64 |
| SYN-18 nested struct overrun | CWE-787 | The copy overruns `secret_key[64]` but stays inside the enclosing object; ASan tracks allocation, not intra-object, boundaries |
| SYN-19 macro UAF | CWE-416 | `SAFE_FREE` nullifies the pointer and the guard short-circuits — no live use-after-free |
| SYN-20 opaque pointer | CWE-457 | Uninitialised heap read requires MSan; the read stays inside the allocation |
| cJSON × 6 | CWE-676 | Real Semgrep `p/security-audit` findings (unbounded string-copy APIs), **not CVEs** — no exploit exists. Gated on compiling the whole library and keeping cJSON's upstream test suite green under ASan + UBSan |

Every PoV that *is* used was pre-flighted: the target is compiled unpatched and
the PoV executed against it, so each gate is known to detect a real bug before it
may decide anything. All 21 reproduced.

---

## 4. Suite Detail

### A. Project Vanguard-0 — nightmare suite

Original synthetic targets exercising structure that defeats snippet-level
reasoning. Not derived from any public dataset.

| Target | CWE | Vulnerability | Result | Agent | Hardening |
| :--- | :--- | :--- | :---: | :---: | :--- |
| VANGUARD-01-BITFIELD-OVERFLOW | CWE-122 | Payload length in a packed bitfield header, declared in a separate header, overruns `buffer[128]` | PATCHED | beta | SURVIVED — differential, 23 inputs |
| VANGUARD-02-ASYNC-UAF-ALIAS | CWE-416 | Use-after-free reached through an aliased global `SessionHandle` in a cleanup callback | PATCHED | gamma | SURVIVED — differential, 25 inputs |
| VANGUARD-03-MACRO-UNDERFLOW | CWE-191 | Allocation size wraps through chained macros `CALC_ALLOC_SZ` → `EXPAND_BUF` | PATCHED | beta | SURVIVED — differential, 22 inputs |
| VANGUARD-04-RTOS-URI-TRAVERSAL | CWE-22 | Custom `rtos://` URI concatenated into a storage root without sanitisation | PATCHED | beta | SURVIVED — evasion battery, no bypass |

### B. CVE-inspired synthetic extension

Original ~30–50 line reproductions of the *shape* of well-known bug classes.
**Not** the referenced upstream code or CVEs.

| Target | CWE | Vulnerability | Result | Agent | Hardening |
| :--- | :--- | :--- | :---: | :---: | :--- |
| SYNTH-TIFF-CROP-OOB | CWE-125 | Crop box indexed against the source image without validating it against the image's real extent (modelled on the shape of CVE-2016-5321) | PATCHED | gamma | SURVIVED — re-fuzz clean |
| SYNTH-SERVICE-STACK-OVERFLOW | CWE-121 | Unbounded `strcpy` into a fixed 64-byte packet body (styled after a CGC service) | PATCHED | alpha | SURVIVED — differential, 25 inputs |

### C. Synthetic 0-day suite (20 targets, comment-free)

| ID | Vulnerability | CWE | Patch strategy |
| :--- | :--- | :--- | :--- |
| SYN-01 | Magic bytes / integer overflow | CWE-190 | Bounded allocation against `sizeof(NetworkPacket)` |
| SYN-02 | Deep typedef confusion | CWE-787 | AST-extracted `u8 key[64]` to bound the copy |
| SYN-03 | Silent integer overflow | CWE-190 | Guarded multiplication against `UINT32_MAX / size` |
| SYN-04 | Extreme integer truncation | CWE-197 | Bounded 64→32-bit truncation before allocation |
| SYN-05 | Conditional double free | CWE-415 | Nullified pointer on the early error exit |
| SYN-06 | Off-by-one loop | CWE-193 | Critic-guided string-termination boundary fix |
| SYN-07 | Format string | CWE-134 | Explicit `%s` specifier |
| SYN-08 | Path traversal | CWE-22 | Rejects `../` under a `restrict` contract |
| SYN-09 | Command injection | CWE-78 | Digit/dot allowlist under a `restrict` contract |
| SYN-10 | Null pointer dereference | CWE-476 | NULL validation after `malloc()` |
| SYN-11 | OOB multidimensional array | CWE-125 | Column index bounds check |
| SYN-12 | Integer underflow | CWE-191 | Asserted `chunk_start < chunk_end` |
| SYN-13 | TOCTOU race | CWE-367 | Structural assertion across the check/use gap |
| SYN-14 | Uninitialised memory | CWE-457 | Zero-initialised stack struct |
| SYN-15 | Hardcoded secret key | CWE-321 | Refactored key out of static scope |
| SYN-16 | Type confusion via union | CWE-843 | Sanitised union member access |
| SYN-17 | Memory leak on error path | CWE-401 | Validation moved before allocation |
| SYN-18 | AST deep struct overflow | CWE-787 | Typedef extracted to bound `secret_key[64]` |
| SYN-19 | AST macro use-after-free | CWE-416 | `SAFE_FREE` expansion made explicit |
| SYN-20 | AST opaque pointer uninit | CWE-457 | `OpaqueState` layout resolved for `memset` |

### D. Fuzz Discovery — fuzz → triage → locate → patch → verify

The fuzzer receives a harness, not a bug location. File and line come from the
crash's own stack trace; the crashing input then becomes the PoV gate.

| Target | Crashes | Distinct bugs | Discovered location | Verified |
| :--- | ---: | ---: | :--- | :---: |
| SYN-02 deep typedef | 1 | 1 | `02_deep_typedef_confusion.c:24` | ✅ |
| SYN-06 off-by-one | 1 | 1 | `06_off_by_one_loop.c:10` | ✅ |
| SYN-12 int underflow | 1 | 1 | `12_integer_underflow.c:8` | ✅ |

---

## 5. Verification Model

| Gate | Check |
| :--- | :--- |
| **Apply** | Diff applies to a pristine copy; ambiguous hunks refused. Whole-function replacements are spliced by AST range |
| **Build** | Compiles under ASan + UBSan with `-fno-sanitize-recover=all`, so a sanitizer report is a hard failure |
| **PoV replay** | The crashing input, replayed against the **rebuilt patched binary**, must no longer trip a sanitizer |
| **Regression** | A benign input still exits 0, stays sanitizer-clean, and produces the expected output |
| **Post-patch scan** | Semgrep reports no findings the original lacked |
| **Hardening** | Adversarial re-fuzzing, differential execution, and the evasion battery (§2) |

A gate with no command configured is recorded `SKIPPED` and is never counted as a
pass. Reports distinguish "the PoV proved the fix" from "no PoV existed".

---

## 6. Patch Quality, Resources & Memory

| Metric | Measured Value |
| :--- | :--- |
| Compilation success rate | **100%** — every validated patch compiled under ASan + UBSan |
| Regression pass rate | **100%** — no validated patch broke a configured regression check |
| Input tokens | 123,030 (main harness run) |
| Output tokens | 37,971 (main harness run) |
| API calls | 124 (main harness run) |
| **Total cost, all 37 targets** | **$0.0521** |
| Peak RSS (harness process) | 1,361 MB |
| Semantic memory patterns learned | 24 |
| Episodic trajectories recorded | 29 |

Memory records only gate-validated outcomes: a fix enters semantic memory because
the gates proved it, never because an agent asserted it. Pitfalls are stored as
observations rather than conclusions, and a pattern's confidence decays if it is
recalled and the repair still fails.

---

## 7. Not Measured

- **Patch size** — the metric counted unified-diff markers, which is zero for the
  whole-function format most patches now use. Corrected to diff the file before
  and after; valid from the next run.
- **Detection precision / recall** — this evaluation patches curated target lists
  and fuzzes four harnesses. No labelled detection corpus was scanned, so neither
  figure can be derived.
- **CPU utilisation** — not sampled.
- **Concolic execution** — the Driller/angr engine is implemented but its
  known-answer self-test fails on arm64 Mach-O, so it disables itself rather than
  emit unverifiable results. Nothing here depends on it; the same code self-tests
  successfully on x86-64 ELF.
- **AFL++ campaign results** — AFL++ is installed and verified to find crashes
  (635 executions on SYN-02), but the reported fuzz suite used libFuzzer.

### Component availability, probed during the run

| Component | State |
| :--- | :--- |
| Fuzzing engines | libFuzzer **and** AFL++ available |
| Crash triage backend | native AddressSanitizer engine (CASR not installed — requires Rust) |
| Semgrep | available (1.172.0) |
| Concolic (Driller/angr) | disabled by self-test on this platform |

---

## 8. Scope of These Results

The corpus is 37 targets: 26 purpose-built synthetic samples, 2 NIST Juliet cases,
6 real Semgrep findings in cJSON, and 3 fuzzer-discovered bugs. All results use
`gpt-4o-mini` on a single macOS host.

Sixteen targets cannot be dynamically proven on this platform (§3); running on
x86-64 Linux would enable MemorySanitizer, LeakSanitizer and the concolic engine,
moving several of them into the provable set.

Hardening is *falsification*, not proof: surviving it means the patch could not be
broken within the budget given, not that it is provably correct.

---

## 9. Reproducing

```bash
# Main harness — synthetic, Juliet, cJSON, fuzz discovery
python benchmark.py --suite all --fuzz --harden --memory --fuzz-seconds 30

# Standalone suites
python -m tests.vanguard_nightmare.run_vanguard
python -m tests.public_benchmarks_extension.run_public_benchmarks

# Unit tests — no API calls, no network
python -m pytest tests/unit -q     # 77 tests
```
