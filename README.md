# AI Kavach CRS — Autonomous Cyber Reasoning System

An autonomous Cyber Reasoning System for the **Indian Army Terrier Cyber Quest 2026**.

AI Kavach **finds** memory-safety bugs in C/C++ by fuzzing, **locates** them from
the crash's own stack trace, **explains and patches** them with a multi-agent LLM
ensemble, and — the part that matters — **proves the fix** by rebuilding the code
and replaying the exact crashing input against the patched binary.

Then it goes further: it **tries to break its own patches**. A fix that merely
turns the gates green is not trusted until re-fuzzing and differential testing
have failed to falsify it.

If a patch cannot be shown to work, it is not reported as working.

**Latest measured run (2026-08-30):** 44/44 targets patched — 100%, 95% CI
[92.0, 100.0] — 30/30 dynamically proven against the original exploit, $0.0739
total, 125 unit tests green.

Of the 44 patches, **32 were actively attacked and none broke**. Five had no
applicable falsification check and are reported NOT HARDENED rather than counted
as survivors — including two whose differential test compares *zero* inputs and
which a previous run had wrongly credited. Full detail and caveats in
[`benchmark.md`](benchmark.md).

A 95% CI is quoted because 44/44 is not evidence of a 100% rate, and a corpus
everything passes has stopped discriminating — the next useful step is harder
targets, not a better score here.

### Resource footprint

Measured on one MacBook (Darwin arm64), no GPU, no cluster, no fine-tuning:

| | Measured |
| :--- | ---: |
| Total LLM cost, 44 targets | **$0.0739** (median $0.0009/target) |
| Total wall time, 7 suites | **804s** (median 5.8s/target) |
| Peak RSS, harness process | **1,300 MB** — fits an 8 GB laptop |
| Local model weights on disk | **0 bytes** — inference is an API call |
| ML frameworks in the dependency tree | **0** (no torch / CUDA / TensorFlow / JAX) |
| Python environment | 824 MB · clang 80 MB · Semgrep 75 MB · AFL++ 112 KB |

The cost is low because the expensive work is done by tools that are not billed
by the token — clang, AddressSanitizer, libFuzzer, CBMC. The LLM only *proposes*
patches; deterministic verification accepts or rejects them. That is why a small
model suffices: a weaker model yields worse candidates and the gates reject them,
so model capability trades against iteration count, not against correctness.

CPU utilisation is not sampled, and is reported as unmeasured rather than
estimated. Full breakdown: [`benchmark.md`](benchmark.md) §6.

### Model and provider

These results were measured with **`gpt-4o-mini`** via the OpenAI API — a small,
cheap model, chosen deliberately: $0.0739 for 44 targets is the "lightweight"
claim, and it holds only because the verification does the hard work rather than
the model.

**The provider is not fixed.** The client was written against the OpenAI
*protocol*, not the OpenAI *service*, so any OpenAI-compatible endpoint works
with no code change — a self-hosted **vLLM**, **llama.cpp**, **Ollama**, or an
internal gateway:

```bash
export OPENAI_BASE_URL=http://10.0.0.5:8000/v1   # your local / on-prem endpoint
export OPENAI_API_KEY=whatever-your-endpoint-wants
export MODEL_ALPHA=... MODEL_BETA=... MODEL_GAMMA=...
```

That matters for air-gapped deployment, where LLM inference is the *only*
component that needs a network at all — see
[Running offline / air-gapped](#running-offline--air-gapped).

Stated plainly: **patch quality on a different model is not measured here.** The
verification gates are model-independent and would catch a weaker model's bad
patches, but the pass rate would need re-measuring on whatever you deploy. That
is one command.

---

## Quick Start

```bash
conda activate ai_kavach
pip install -r requirements.txt

# Verify configuration (models come from .env)
python -c "from config import get_llm_config; print(get_llm_config()['models'])"
```

**Run the benchmark**

```bash
# Everything: curated suites + fuzz-discovery + hardening + memory + formal proof
python benchmark.py --suite all --fuzz --harden --memory --formal --fuzz-seconds 30

# Just the curated suites plus fuzz-discovery
python benchmark.py --suite all --fuzz --fuzz-seconds 30

# Re-run only specific targets (e.g. ones that failed)
python benchmark.py --suite synthetic --only SYN-06-OFF-BY-ONE,SYN-09-CMD-INJECTION

# Just the curated suites
python benchmark.py --suite all

# Only the fuzz-discovery suite
python benchmark.py --suite fuzz --fuzz-seconds 30

# One suite, quick pass
python benchmark.py --suite synthetic --limit 5
```

**Run against your own code**

```bash
python -m src.main --target /path/to/code \
    --build-cmd 'clang -fsanitize=address,undefined -fno-sanitize-recover=all "{src}" -o "{bin}"' \
    --pov-cmd   'sh repro.sh "{bin}"' \
    --test-cmd  'make check'
```

`{src}`, `{srcdir}`, `{bin}` and `{workspace}` are substituted with the *patched*
copy — so your commands test the patch, not the original. `--pov-cmd` must exit
**0 only when the vulnerability is absent**. Without it the PoV gate is skipped
and the run will tell you the patch is unproven.

**Run the tests**

```bash
python -m pytest tests/unit -q     # 125 tests, no API calls, no network
```

---

## What is actually implemented

| Component | Status |
|---|---|
| Coverage-guided fuzzing | **Working** — libFuzzer *and* AFL++ drive one shared harness (`src/analysis_engine/fuzzer_manager.py`) |
| Crash triage & deduplication | **Working** — replays each crash, parses the sanitizer report, maps crash class → CWE, clusters by root cause (`crash_triage.py`). Uses CASR when `casr-san` is on PATH, native ASan triage otherwise |
| Fuzz → triage → patch → verify | **Working** — `src/fuzz_pipeline.py`, via `benchmark.py --fuzz` |
| Semgrep static analysis → SARIF | **Working** — `p/security-audit` ruleset, SARIF v2.1.0 |
| Tree-sitter AST context engine | **Working** — pulls the enclosing function plus the structs/typedefs it references |
| Multi-agent ensemble (Alpha/Beta/Gamma) | **Working** — parallel; among agents that clear every gate, the smallest patch wins |
| Agent Delta (Critic) | **Working** — LLM-as-judge with a strict JSON verdict; diagnoses *why* a patch was rejected instead of handing the agent a raw sanitizer dump |
| DRV verification loop | **Working** — apply → build (ASan+UBSan) → PoV replay → regression → static re-scan |
| Patch hardening | **Working** — re-fuzzes the patched build and differential-tests it against the original, to catch patches that only *look* fixed (`--harden`) |
| Agent memory | **Working** — working (attempt ledger, in-loop), episodic (trajectory log), semantic (cross-target fix patterns, recalled into the prompt with decaying confidence); only gate-validated fixes are ever learned (`--memory`). Procedural memory **records** which agent wins per CWE and how many iterations it took, but nothing consumes it yet — `preferred_agent_order()` and `suggested_iterations()` exist and are tested, and are not wired into routing or budgeting |
| Real published CVEs | **Working** — 3 real defects in unmodified upstream cJSON (CVE-2019-11835, CVE-2019-11834, GH-800); latest run **3/3**, all PoV-proven and hardened. Self-contained in `tests/real_cve_suite/`; the only suite whose provenance is external |
| Bounded formal verification | **Working** — CBMC proves the patched function safe for **all** inputs within a per-target unwind bound (`--formal`). Requires a proof harness; targets without one report `unavailable`, never proven |
| Benchmark harness + reporting | **Working** — every reported figure is measured; nothing is a constant |
| Driller / angr concolic fallback | **Implemented, self-gated** — plateau detection and symbolic solving are real, but the engine runs a known-answer test first and **disables itself** where angr can't tie symbolic input to a comparison (it can't on arm64 macOS; it can on x86-64 Linux) |

---

## Verification model

A patch is reported as validated **only** when every gate configured for that
target actually ran and passed:

| # | Gate | Check |
|---|---|---|
| 0 | **Apply** | The diff applies to a pristine copy. Exact context first; a content-matching fallback places hunks whose line numbers drifted and refuses any it cannot place *uniquely*. |
| 1 | **Build** | Compiles under ASan + UBSan with `-fno-sanitize-recover=all`, so a sanitizer report is a hard failure, not a warning. |
| 2 | **PoV replay** | The exact input that crashed the original is replayed against the **patched** binary and must no longer trip a sanitizer. |
| 3 | **Regression** | A benign input must still exit 0, stay sanitizer-clean, and print what it used to. |
| 4 | **Post-patch scan** | Semgrep must not report findings the original did not have. |

### Hardening: gates alone are gameable

Passing every gate is not proof. Three cheap attacks defeat gate-only verification,
and each is what a model optimising for a green gate would naturally produce:

| Attack | Clears every gate? | Caught by |
|---|:---:|---|
| **PoV overfitting** — special-case the crashing input (`if (size == 4) return;`) | yes | **Adversarial re-fuzzing** of the patched build |
| **Functionality gutting** — disable the code path with an early `return` | yes | **Differential testing** against the original on benign inputs |
| **Incomplete validation** — a sanitiser a cleverer payload slips past | yes | **Evasion battery** — bypass encodings (`....//`, `sub/../../`, `.././`) |

`--harden` runs them. A patch that fails is downgraded, not reported as a fix.
Which checks apply depends on the fix's behavioural contract: memory-safety fixes
(`preserve`) must not change behaviour the original got right, while
input-validation fixes (`restrict`) are *supposed* to reject inputs the original
accepted, so they are held to the evasion battery instead of differential
equivalence. Holding a `restrict` fix to `preserve` produces a false falsification,
which is why the contract is declared per target in `tests/benchmarks/targets.py`.

This is not decorative. In the 2026-08-30 run, **two patches that had passed
every gate were falsified here**: SYN-15 changed observable output on a benign
input, and SYN-16 still crashed under re-fuzzing. Both would have been reported
as fixes on gate evidence alone.

**`--formal` goes further still.** Every check above is empirical — it runs the
program on inputs we chose. CBMC compiles the patched function into a logical
formula and asks an SMT solver whether *any* input violates a safety property.
Measured value: an overfitted patch (`if (col == 1000000) return -1;`) **passes
the PoV gate** and is **caught by CBMC**, on a target that has no fuzz harness
so re-fuzzing could not have caught it either. The claim is always *bounded* —
"no violation within unwind K" — and the bound is reported with the result.
Both countermeasures are verified against deliberately-cheating patches in the
test suite, and verified not to flag honest fixes.

Three further rules keep the numbers meaningful:

- **`SKIPPED` is never a pass.** A gate with no command is reported as skipped,
  with the reason. Reports separate "the PoV proved the fix" from "no PoV existed".
- **Every PoV is pre-flighted.** Before any agent runs, the target is compiled
  *unpatched* and the PoV executed against it. A PoV that doesn't reproduce is
  disabled — so a patch can never be credited for fixing something never shown broken.
- **Targets with no runtime manifestation say so.** Weaknesses that can't be
  demonstrated on this platform (leaks needing LSan, uninitialised reads needing
  MSan, intra-struct overruns ASan can't see, races) carry a written reason in
  `tests/benchmarks/targets.py` and are never counted as PoV-verified.
- **Harnesses must respect the target's preconditions.** A fuzz harness that
  passes a count exceeding the buffer it supplies makes a function *unfixable by
  contract* and produces false failures. This bit us once; a regression test now
  scans for it. See `tests/fuzz_harnesses/README.md`.

---

## Architecture

```
             ┌──────────────── DETECTION ────────────────┐
             │                                           │
  Semgrep (SARIF)                        Fuzzing (libFuzzer / AFL++)
             │                            ASan + UBSan instrumented
             │                                           │
             │                                    crash inputs
             │                                           ▼
             │                            Crash Triage — replay, parse
             │                            sanitizer report, dedup by
             │                            root cause, map → CWE
             │                                           │
             │                          coverage plateau ├──▶ Driller / angr
             │                                           │    (self-gated)
             └──────────────┬────────────────────────────┘
                            ▼
                 Vulnerability Report  (file + line from the crash trace)
                            │
                            ▼
                 Tree-sitter Context Engine
              (function + structs + typedefs)
                            │
                            ▼
                 Multi-Agent Orchestrator
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
      Alpha               Beta                Gamma
    (analyst)         (minimalist)        (SARIF fixer)
        └───────────────────┼───────────────────┘
                            ▼
                  DRV Verification Loop
       apply → build → PoV replay → regression → re-scan
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
      failure fed back              Verified Patch
      to the agents                (smallest wins)
                                          │
                                          ▼
                              Audit Report — per-gate
                              PASS / FAIL / SKIPPED
```

---

## Project layout

```
benchmark.py                     Master benchmark harness (measured metrics only)
config/                          Model + API configuration, agent system prompts
src/
  main.py                        CLI pipeline entry point
  fuzz_pipeline.py               fuzz → triage → patch → verify
  analysis_engine/
    fuzzer_manager.py            libFuzzer + AFL++ build and campaign control
    crash_triage.py              Crash replay, sanitizer parsing, dedup, CWE mapping
    driller_monitor.py           angr concolic engine + AFL plateau detection
    semgrep_runner.py            Static analysis → SARIF
  context_engine/
    tree_sitter_extractor.py     AST-aware context extraction
  agent_orchestrator/
    orchestrator.py              Parallel ensemble, winner selection, memory I/O
    critic.py                    Agent Delta + the escalation policy
    llm_client.py                OpenAI client, retries, token/cost accounting
  memory/
    store.py                     Working / episodic / semantic / procedural memory
  patch_validator/
    drv_loop.py                  The verification gates + deterministic loop control
    hardening.py                 Re-fuzzing + differential falsification
  reporting/
    audit_report.py              Audit trail with real per-gate outcomes
tests/
  benchmarks/targets.py          Target manifest + verification contract per target
  benchmarks/harness/            PoV and regression runner scripts
  fuzz_harnesses/                libFuzzer-style harnesses + shared AFL driver
  demo_vulns/                    20 synthetic vulnerable programs
  unit/                          Unit tests
```

---

## Platform notes

- **libFuzzer:** Apple's `/usr/bin/clang` does not ship the fuzzer runtime.
  Homebrew LLVM does, and is auto-detected at `/opt/homebrew/opt/llvm/bin/clang`.
- **AFL++ on macOS:** aborts with `shmget() failed` under the default SysV
  shared-memory limits. The fuzzer manager sets `AFL_MAP_SIZE=65536`
  automatically, which works without root. For full-size maps: `sudo afl-system-config`.
- **angr on arm64 macOS:** imports and explores, but fails its known-answer test,
  so concolic results are disabled rather than reported. Works on x86-64 Linux.
- **CASR:** not installed (needs Rust). The native triage engine is used and is
  automatically superseded by CASR if it appears on PATH.

Model configuration lives in `config/__init__.py` — `MODEL_ALPHA` / `MODEL_BETA` /
`MODEL_GAMMA` environment variables, default `gpt-4o-mini`.

---

## Running offline / air-gapped

Relevant because the intended deployment is defence infrastructure, where
outbound internet is often unavailable. The short answer: **exactly one
component needs the network, and it can be pointed at a local endpoint.**

| Stage | Network needed? | Detail |
|---|---|---|
| Fuzzing (libFuzzer, AFL++) | **No** | Local toolchain; campaigns run in-process against a local corpus |
| Build + sanitizers (clang, ASan/UBSan) | **No** | Local compiler |
| Crash triage | **No** | Replays the crash locally and parses the sanitizer report |
| Tree-sitter context engine | **No** | Grammars are installed Python wheels |
| Semgrep static analysis | **Only to fetch rules the first time** | `SemgrepRunner(rules=...)` accepts a **local YAML path** as well as a registry reference — verified running with a vendored rules file and no registry access |
| CBMC bounded verification | **No** | Local solver |
| Patch hardening (re-fuzz, differential, evasion) | **No** | All local execution |
| **LLM inference** | **Yes** | The only external dependency |

`grep` for outbound HTTP in `src/` returns nothing: every network call goes
through the OpenAI SDK, and its base URL is configurable.

**Pointing at an on-prem model.** `config/__init__.py` reads `OPENAI_BASE_URL`
and passes it straight to the client, so any OpenAI-compatible server works —
vLLM, llama.cpp, Ollama, or an internal gateway:

```bash
export OPENAI_BASE_URL=http://10.0.0.5:8000/v1     # your vLLM / gateway
export OPENAI_API_KEY=whatever-your-endpoint-wants
export MODEL_ALPHA=... MODEL_BETA=... MODEL_GAMMA=...
python benchmark.py --suite all
```

No code change is required — the client was written against the OpenAI
*protocol*, not the OpenAI *service*.

**Vendoring the Semgrep rules.** On a connected machine, fetch the pack once and
carry the YAML across; then construct the runner with that path instead of
`p/security-audit`. The scanner treats a local file and a registry reference
identically.

**Honest caveat.** Results in `benchmark.md` were measured with `gpt-4o-mini`
over the public API. Swapping in a local model changes patch quality, and by how
much is **not measured here** — the verification gates are unchanged and would
catch a weaker model's bad patches, but the pass rate would need re-measuring on
whatever model you deploy. The harness makes that a single command.

---

## Documentation

| File | Contents |
|---|---|
| `architecture.md` | Full five-phase design and component diagram |
| `benchmark.md` | Measured results from the latest run |
| `INSTALLED.md` | Everything installed, with uninstall commands |
