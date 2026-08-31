# AI Kavach CRS — Benchmark & Evaluation Results

**Platform:** Darwin arm64 / Python 3.11.15
**Mode:** parallel multi-agent ensemble (Alpha + Beta + Gamma + Delta Critic)
**Models:** `gpt-4o-mini` for all agents, via the OpenAI API.
**Provider is swappable** — the client targets the OpenAI *protocol*, so any
compatible endpoint (self-hosted vLLM / llama.cpp / Ollama / internal gateway)
works by setting `OPENAI_BASE_URL`, with no code change. Every figure below was
measured on `gpt-4o-mini`; results on another model would need re-measuring.
**Architecture:** [`architecture.md`](architecture.md)

> Every figure in this document was measured during execution. Quantities that
> could not be measured on this platform are listed in §8 rather than estimated.

---

## 1. Headline Results

Run **2026-08-30**, artifacts in `reports/benchmark_runs/20260830_094305/` plus
the three standalone reports. One evaluation pass. Nothing was re-run to improve
a number, and the suites below are the whole corpus, not a selection.

| Suite | Targets | Passed all gates | Rate | PoV-proven | Time |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Synthetic | 20 | 20 | 100% | 12 / 12 | 403.3s |
| NIST Juliet | 2 | 2 | 100% | 2 / 2 | 18.8s |
| Real World (cJSON, 3,000+ lines) | 6 | 6 | 100% | – | 76.3s |
| Real published CVEs (unmodified cJSON) | 3 | 3 | 100% | 3 / 3 | 74.4s |
| Fuzz Discovery (libFuzzer) | 7 | 7 | 100% | 7 / 7 | 122.0s |
| Project Vanguard-0 (nightmare suite) | 4 | 4 | 100% | 4 / 4 | 68.8s |
| CVE-inspired synthetic extension | 2 | 2 | 100% | 2 / 2 | 40.2s |
| **Total** | **44** | **44** | **100%** | **30 / 30** | **804s** |

**Passed all gates: 44/44 — 100%, 95% CI [92.0, 100.0]**
**PoV-proven: 30/30 — 100%, 95% CI [88.6, 100.0]**
**Cost: $0.0739** · 161 API calls · 244,643 in / 46,175 out · `gpt-4o-mini`
**Unit tests: 125**, no API calls, no network

A 95% confidence interval is quoted because 44/44 is not evidence of a 100% rate.
The interval says the true rate is unlikely to be below ~92% *on this corpus*;
it says nothing about code the system has not seen.

### Hardening: 32 attacked, 0 falsified, 5 not attacked

This is reported as three numbers rather than one, because the previous single
figure hid the distinction that matters:

| | Count |
| :--- | ---: |
| Patches actively attacked, and held | **32** |
| Patches falsified by an attack | **0** |
| Patches with no applicable falsification check — reported NOT HARDENED, never as passes | **5** |

The five are SYN-08 and SYN-09 (`restrict` contract, no fuzz harness, no evasion
battery), SYN-15 (`replace` contract — its only discriminator is the PoV gate,
and re-running it post-hoc would recount evidence already counted), and
JULIET-CWE121/416, whose differential test compares **zero** inputs because the
tester skips inputs on which the original crashes.

Those last two were previously counted as "survived". They were not: nothing had
been compared. `HardeningVerdict.survived` now requires that a check actually
produced a result, so the hardening figure went *down* when the accounting was
corrected — 34/36 in the previous run was partly unearned.

### Fuzz Discovery counts bugs, not harnesses

Nine harnesses were fuzzed for 30s each, producing 8 crash inputs that triaged to
7 distinct bugs, all 7 repaired and PoV-proven. Harnesses that find nothing are
not counted as unrepaired targets — there was nothing to repair.
`BenchmarkHarness.check_suite_units` rejects that unit mismatch, which had
previously reported a run as 34/39 while the suite's own rate said 6/7.

### The three bars, in increasing strength

1. **Passed all gates (44/44)** — the patch applied cleanly, compiled under
   AddressSanitizer + UndefinedBehaviorSanitizer with `-fno-sanitize-recover=all`,
   and cleared every check configured for that target.
2. **PoV-proven (30/30)** — the exact input that crashed the original no longer
   does, replayed against the *rebuilt patched binary*. Fourteen targets have no
   reproducible runtime exploit here (§3) and cannot earn this bar.
3. **Survived hardening (32)** — actively attacked and held; five more had no
   applicable attack and are not counted (above).

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
- **`replace`** (a compiled-in value must change: hardcoded secrets, CWE-321) —
  the program's output is *required* to differ from the original, so demanding
  equivalence is unsatisfiable. Before this contract existed it falsified a
  correct patch, on the grounds that output changed on the benign input `42`.

No check may pass vacuously. The evasion battery reports *inconclusive* if
legitimate access is broken, so a patch that rejects everything cannot score as
hardened; and `SURVIVED` requires that a falsification attempt actually ran.

---

## 3. Coverage of the PoV bar

Fourteen of the 44 targets have no reproducible runtime exploit on this platform. Each
carries a written reason in its manifest, is reported `SKIPPED`, and is never
counted as PoV-proven:

| Target | CWE | Why no PoV exists on this platform |
| :--- | :--- | :--- |
| SYN-01 magic bytes | CWE-190 | The overflow path is unreachable from the entrypoint: the version field `0x0100` contains a NUL byte, so no argv string satisfies the header guards |
| SYN-08 path traversal | CWE-22 | The hardcoded base directory `/var/www/html/users` does not exist; creating it requires root |
| SYN-10 null deref | CWE-476 | The 800 KB allocation never fails, so the missing NULL check never manifests |
| SYN-13 TOCTOU | CWE-367 | Winning the race requires a concurrent attacker; not deterministic in-process |
| SYN-14 uninit read | CWE-457 | Requires MemorySanitizer (Linux-only); ASan does not model uninitialised memory |
| SYN-18 nested struct overrun | CWE-787 | The copy overruns `secret_key[64]` but stays inside the enclosing object; ASan tracks allocation, not intra-object, boundaries |
| SYN-19 macro UAF | CWE-416 | `SAFE_FREE` nullifies the pointer and the guard short-circuits — no live use-after-free |
| SYN-20 opaque pointer | CWE-457 | Uninitialised heap read requires MSan; the read stays inside the allocation |
| cJSON × 6 | CWE-676 | Real Semgrep `p/security-audit` findings (unbounded string-copy APIs), **not CVEs** — no exploit exists. Gated on compiling the whole library and keeping cJSON's upstream test suite green under ASan + UBSan |

Two entries left this table after being re-examined, and both are worth naming
because the stated reason had been wrong rather than merely conservative:

- **SYN-15 (CWE-321)** was listed as "statically observable only". A PoV does not
  have to be a crash — the contract is *exit 0 only when the weakness is absent*,
  and `strings` on the built binary decides that. It is now a pre-flighted gate.
- **SYN-17 (CWE-401)** was listed as needing a LeakSanitizer "unsupported on
  darwin-arm64". The blocker was the toolchain, not the platform: Apple's ASan
  runtime reports `detect_leaks is not supported on this platform`, Homebrew
  LLVM's runtime does support it on this same host. SYN-17 now builds with that
  runtime and is gated by `pov_leak.sh`.

Every PoV that *is* used was pre-flighted: the target is compiled unpatched and
the PoV executed against it, so each gate is known to detect a real bug before it
may decide anything. All 28 reproduced on their unpatched originals.

---

## 4. Suite Detail

### A. Project Vanguard-0 — nightmare suite

Original synthetic targets exercising structure that defeats snippet-level
reasoning. Not derived from any public dataset.

| Target | CWE | Vulnerability | Result | Agent | Hardening |
| :--- | :--- | :--- | :---: | :---: | :--- |
| VANGUARD-01-BITFIELD-OVERFLOW | CWE-122 | Payload length in a packed bitfield header, declared in a separate header, overruns `buffer[128]` | PATCHED | beta | SURVIVED — differential, 23 inputs |
| VANGUARD-02-ASYNC-UAF-ALIAS | CWE-416 | Use-after-free reached through an aliased global `SessionHandle` in a cleanup callback | PATCHED | alpha | SURVIVED — differential, 25 inputs |
| VANGUARD-03-MACRO-UNDERFLOW | CWE-191 | Allocation size wraps through chained macros `CALC_ALLOC_SZ` → `EXPAND_BUF` | PATCHED | beta | SURVIVED — differential, 22 inputs |
| VANGUARD-04-RTOS-URI-TRAVERSAL | CWE-22 | Custom `rtos://` URI concatenated into a storage root without sanitisation | PATCHED | beta | SURVIVED — evasion battery, no bypass |

### B. Real published CVEs — unmodified upstream source

The only suite whose provenance is external. Each tree is upstream cJSON checked
out at the commit immediately *before* the security fix landed, so the defect is
the one that shipped. Self-contained and re-runnable via `tests/real_cve_suite/`.

| Target | Defect | Observed outcome | Hardening |
| :--- | :--- | :--- | :--- |
| CVE-2019-11835 `cJSON_Minify` | On an unterminated `/*` the scan loop halts at the NUL and the following `json += 2` steps past it | **PATCHED** (agent beta) — stable across runs | SURVIVED — differential, 25 inputs |
| GH-800 `parse_object` | After a comma the parser never checked that anything follows, so a trailing comma in a length-bounded buffer reads past the allocation | **PATCHED** (agent alpha) — stable across runs | SURVIVED — differential, 25 inputs |
| CVE-2019-11834 `parse_string` | `input_end` is dereferenced in **two** places without a prior bounds check: the loop test (C's `&&` is ordered, so the read precedes the check) and the check immediately after the loop | **PATCHED** (agent alpha) | SURVIVED — differential, 25 inputs |

**This run: 3/3 passed all gates, 3/3 PoV-proven, 3/3 survived hardening**
(`reports/real_cve_report.md`).

Every target was validated in both directions before being accepted — the PoV
reproduces on the vulnerable commit and the upstream fix resolves it:

```
CVE-2019-11835  '/*'                       -> heap-buffer-overflow READ cJSON.c:2642
CVE-2019-11834  '"abc'                     -> heap-buffer-overflow READ cJSON.c:660
GH-800          '{"1":1,' (exact-size buf) -> heap-buffer-overflow READ
```

GH-800 has **no assigned CVE**; the upstream commit references GitHub issue #800.
It is named for the issue rather than given an invented CVE number.

#### What made CVE-2019-11834 reliable

It was solved in 6 of 8 earlier runs and is now solved directly. Two of the three
causes were defects in our own harness, not agent capability:

- **The target description was wrong.** It said the upstream fix was "reordering
  the two conditions". Checking commit `a167d9e` shows it changes **two** lines:
  the reorder at the loop, *and* a bounds check added to the test immediately
  after it. An agent following the description exactly still crashed at the
  second site. The description now states the defect accurately.
- **Patches were being discarded on a formatting detail.** One agent failed
  `generation` 5 times in a row: it returned the corrected function in a plain
  ```` ```c ```` block without the `// FUNCTION:` header, and the parser reported
  "no patch was found". Extraction now infers the name from the block's own
  definition, refusing blocks that define more than one function. The name still
  has to resolve against the file's AST, so a wrong guess fails safely.
- **The Critic had no entry for evaluation order.** C's `&&` is short-circuit and
  left-to-right, so a guard placed to the right of the dereference it protects
  does nothing. That is now one of the patterns it checks for — general C
  knowledge, not a hint about this CVE.

The winning patch is semantically identical to upstream `a167d9e`.

### C. CVE-inspired synthetic extension

Original ~30–50 line reproductions of the *shape* of well-known bug classes.
**Not** the referenced upstream code or CVEs.

| Target | CWE | Vulnerability | Result | Agent | Hardening |
| :--- | :--- | :--- | :---: | :---: | :--- |
| SYNTH-TIFF-CROP-OOB | CWE-125 | Crop box indexed against the source image without validating it against the image's real extent (modelled on the shape of CVE-2016-5321) | PATCHED | beta | SURVIVED — `restrict` contract, re-fuzz clean |
| SYNTH-SERVICE-STACK-OVERFLOW | CWE-121 | Unbounded `strcpy` into a fixed 64-byte packet body (styled after a CGC service) | PATCHED | alpha | SURVIVED — differential, 25 inputs |

### D. Synthetic 0-day suite (20 targets)

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

### E. Fuzz Discovery — fuzz → triage → locate → patch → verify

The fuzzer receives a harness, not a bug location. File and line come from the
crash's own stack trace; the crashing input then becomes the PoV gate.

Nine harnesses, 30s each → 8 crash inputs → 7 distinct bugs after triage → **7
repaired and PoV-proven**.

| Discovered target | Repaired |
| :--- | :---: |
| SYN-02-DEEP-TYPEDEF::FUZZ-001 | ✅ |
| SYN-05-DOUBLE-FREE::FUZZ-001 | ✅ |
| SYN-06-OFF-BY-ONE::FUZZ-001 | ✅ |
| SYN-11-OOB-MULTIDIM::FUZZ-001 | ✅ |
| SYN-12-INT-UNDERFLOW::FUZZ-001 | ✅ |
| SYN-16-TYPE-CONFUSION::FUZZ-001 | ✅ |
| SYN-18-AST-DEEP-STRUCT::FUZZ-001 | ✅ |

SYN-05 is worth naming. It was previously discarded as "crash location
unresolved" — at `-O1` the vulnerable function inlines, so ASan reports the
faulting frame as the harness and the target appears only in the *"freed by"*
stack. Three defects in triage compounded it: libFuzzer's own driver units were
not filtered (its entry point is a plain `main`, so a `fuzzer::` filter misses
it), `"attempting double-free"` was captured as the class `"attempting"`, and the
source-root filter computed its result and discarded it, so it had never filtered
anything. It now resolves to `05_double_free_conditional.c:12`, class
`double-free`, CWE-415.

SYN-18 is new: `update_key()` takes an unbounded `key_len`, and although the
program's own `main()` overruns only within the enclosing struct, a caller
passing more than `sizeof(UserSession)` runs off the object — which ASan sees. A
patch clamping the copy survives 25M runs.

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

## 6. Resource Utilisation & Footprint

Measured during the 2026-08-30 run on one MacBook (Darwin arm64, Python 3.11).
No GPU, no cluster, no fine-tuning, no local model weights.

### Cost and time

| Metric | Measured |
| :--- | ---: |
| **Total LLM cost, all 44 targets** | **$0.0739** |
| Median cost per target | $0.0009 |
| Most expensive single target | $0.0129 |
| Total wall time, 7 suites | 804s (13.4 min) |
| Median time per target | 5.8s |
| Slowest single target | 42.6s |
| API calls | 161 |
| Tokens | 244,643 in / 46,175 out |

At $0.0017 per target amortised, scanning a 1,000-target corpus costs under $2.

### Memory and disk

| Metric | Measured |
| :--- | ---: |
| **Peak RSS, harness process** | **1,300 MB** |
| Python environment (all dependencies) | 824 MB |
| clang + LLVM toolchain | 80 MB |
| Semgrep | 75 MB |
| AFL++ | 112 KB |
| CBMC | present, small |
| **Local model weights** | **0 bytes** — inference is a remote API call |
| Source, tests and docs | 1.6 MB |

Peak RSS is `getrusage(RUSAGE_SELF)` for the orchestrator, taken during a run
with three agents in parallel plus fuzzing. It fits comfortably on an 8 GB
laptop, which is where it was measured.

### Why the cost is this low

Not prompt-engineering. The expensive work is done by tools that are not billed
by the token — clang, AddressSanitizer, libFuzzer, CBMC — and the LLM is used
only to propose candidate patches, which are then accepted or rejected by
deterministic verification. That division is what makes `gpt-4o-mini` sufficient:
a weaker model produces worse candidates, and the gates reject them. Model
capability trades against iteration count, not against correctness.

The consequence for deployment: **no GPU is required at any point**, and the
dependency tree contains no ML framework (0 packages matching torch / CUDA /
TensorFlow / JAX). The only stage needing a network is inference, and that can
be redirected to a local endpoint (§4b in `architecture.md`).

### Not measured

- **CPU utilisation** — not sampled. No value is reported rather than estimated.
- **Peak RSS of child processes** — the figure above covers the harness process;
  compiler and fuzzer subprocesses are not aggregated into it.

---

## 7. Patch Quality & Memory

Measured during the 2026-08-30 run.

| Metric | Measured Value |
| :--- | :--- |
| Compilation success rate | **100%** — every validated patch compiled under ASan + UBSan |
| Regression pass rate | **100%** — no validated patch broke a configured regression check |
| Mean patch size | **3.4 lines** (median 2), over the 34 validated patches carrying a measurable diff |
| Formal proofs discharged | **3** — SYN-06 (unwind 70), SYN-11 (16), SYN-12 (20). 28 targets have no proof harness and report `unavailable`, never `proven` |
| Input tokens | 244,643 |
| Output tokens | 46,175 |
| API calls | 161 |
| **Total cost, all 44 targets** | **$0.0739** (~$0.0017 per target) |
| Peak RSS (harness process) | **1,300 MB** — fits an 8 GB laptop |
| Unit tests | **125**, no API calls, no network |
| Semantic memory patterns learned | 28 |
| Episodic trajectories recorded | 91 |

Memory records only gate-validated outcomes: a fix enters semantic memory because
the gates proved it, never because an agent asserted it. Pitfalls are stored as
observations rather than conclusions, and a pattern's confidence decays if it is
recalled and the repair still fails.

---

## 8. Not Measured

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

## 9. Scope of These Results

The corpus is 44 targets: 26 purpose-built synthetic samples (20 comment-free, 4
Vanguard, 2 CVE-inspired), 2 NIST Juliet cases, 6 real Semgrep findings in cJSON,
3 real published defects in unmodified upstream cJSON, and 7 bugs the fuzzer
discovered itself. All results use `gpt-4o-mini` on a single macOS host.

**44/44 is a result about this corpus, not a capability claim.** Three honest
limits on how far it generalises:

- **Only 3 of the 44 are externally sourced.** The rest we wrote, and a corpus
  its own authors designed is a weaker test than one they did not. That is why
  `tests/real_cve_suite/` exists and why its provenance is stated per target.
- **A corpus everything passes has stopped discriminating.** These results say
  the system handles this corpus; they cannot rank it against a stronger one. The
  useful next step is harder targets, not a better score here.
- **Fourteen targets cannot be dynamically proven on this platform** (§3).
  Running on x86-64 Linux would add MemorySanitizer, a libFuzzer-compatible
  LeakSanitizer and the concolic engine, moving several into the provable set.

Hardening is *falsification*, not proof: surviving it means a patch could not be
broken within the budget given. Five patches had no applicable attack at all and
are reported NOT HARDENED rather than counted as survivors (§1).

---

## 10. Reproducing

```bash
# Main harness — synthetic, Juliet, cJSON, fuzz discovery
python benchmark.py --suite all --fuzz --harden --memory --fuzz-seconds 30

# Standalone suites
python -m tests.vanguard_nightmare.run_vanguard
python -m tests.public_benchmarks_extension.run_public_benchmarks

# Unit tests — no API calls, no network
python -m pytest tests/unit -q     # 125 tests
```
