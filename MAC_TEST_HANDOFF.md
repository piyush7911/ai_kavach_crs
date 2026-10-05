# Mac test handoff — finale code written on Windows

**Nothing in this handoff has been run.** The code was written on a Windows machine
with no toolchain. The only check performed was a Python syntax parse (3.11 grammar)
of every new or changed `.py` file: 27 files, 0 errors. Treat every feature below as
untested until the steps in §3 pass on the Mac.

Line endings: a new `.gitattributes` forces LF for all text files (shell scripts
included). All new files were checked and contain no CRLF.

---

## 1. What was written

### Workstream A — autonomous mode (partial)
| File | What |
|---|---|
| `src/autonomy/ingest.py` | Snapshot of the repo into the run dir (sha256 over path + content; no `.git`, no symlinks), census, build detection: flat-c / make / cmake / custom (`--build-cmd`); meson, bazel and autotools without `configure` **fail loudly** and ask for `--build-cmd` |
| `src/autonomy/codeindex.py` | Tree-sitter index: functions, parameters, `static`, call sites with argument text, literal-size local arrays in callers (`#define` sizes resolved), declaring header |
| `src/autonomy/harness.py` | Entry-point search (walks callers of a `static` function up to 3 levels), caller-derived preconditions (literal sets, minimum buffer size, `sizeof` relations), template harnesses (buf+len, C string, integers, caller-sized output buffer), LLM fallback prompt, fairness check |
| `src/autonomy/runner.py` | Stages: ingest → Semgrep → harness, `evidence.json` with a status and reason for every finding, JSONL events |
| `src/main.py` | `--mode auto`, `--run-dir`, `--events`, `--no-llm-harness`, `--max-functions` |
| `src/agent_orchestrator/llm_client.py` | `complete()`: a generic call with token usage recorded |
| `src/patch_validator/drv_loop.py` | **Bug fix**: `_materialise` with an absolute `source_dir` used to copy the tree onto itself |
| `dashboard/app.py`, `static/index.html` | `POST /api/jobs/auto` (repo chosen by id only; no free-text command from the browser), `GET /api/auto/{repo_id}`; the Drop view's Start button runs auto mode and shows the evidence table |
| `docs/autonomy_design.md` | Design note, including the OSS-Fuzz-Gen prior-art line |

**Not written:** compiling the snapshot with sanitizers, the reach judge, the fuzz
campaign, triage, PoV pre-flight, and repair plus hardening for uploaded repos.
The best status in this build is `harness_ready`, with the reason
"build+fuzz stage … not implemented". Nothing from an upload is compiled or executed.

### Workstream E — patch policy gate + verifier red-team
| File | What |
|---|---|
| `src/patch_validator/policy.py` | The rules: `single_file`, `no_test_or_build_edit`, `in_flagged_function` (added `#include` lines allowed), `changed_line_cap` (80), `denied_construct` (signal/sigaction, no_sanitize/optnone/pragma attribute, inline asm, exit/_exit, getenv, setjmp/longjmp; only counts what is *added*; comments and strings ignored) |
| `drv_loop.py` | The policy runs after apply and before build, as gate `policy`. New `PatchResult.policy_ok` and `policy_violations`. `KAVACH_POLICY=off` disables it, and it is then recorded as skipped |
| `orchestrator.py` | Passes `vuln.line_number` as the flagged line |
| `benchmark.py` | New CSV column `Policy_Gate` |
| `tests/cheat_detector/run_redteam.py` | 11 cheat classes + the honest fix. Each candidate goes through policy, gates and hardening independently; JSON output to `reports/special/redteam.json` |
| dashboard | `POST /api/jobs/redteam`; the Special cases card now shows results |

### Workstream F — sandbox + prompt-injection scrub
| File | What |
|---|---|
| `src/patch_validator/sandbox.py` | `KAVACH_SANDBOX=off` (default) / `auto` / `required`. macOS: `sandbox-exec` profile with network denied and writes limited to the gate workspace (TMPDIR moved inside it). Linux: `bwrap` |
| `drv_loop.py` `_run` | All gate commands go through the sandbox plan. In `required` mode with no backend, the gate fails instead of running unconfined |
| `crash_triage.py` | Crash replay goes through the sandbox too |
| `src/context_engine/injection_scrub.py` + `orchestrator.py` | Comments matching injection patterns are replaced by a marker of the same line count before the prompt is built; code and strings are untouched |

### Workstream J — reproducibility bundle
`src/reporting/repro.py`, called at the end of `benchmark.py generate_reports`. Every
run directory gets `tool-versions.json`, `reproduce.sh` (re-runs one target and
compares Status) and `manifest.json` (sha256 of every file, written last). It is
labelled "hash-manifested, not signed".

### Other workstreams
| Item | File | State |
|---|---|---|
| B cloud vs local table | `tests/benchmarks/compare_providers.py` | written; needs two real runs |
| I precision/recall | `tests/benchmarks/detection_eval.py` | written; needs the Juliet C suite; fixed tune/eval split by path hash |
| H defence page | `docs/defence_domain.md` | done; no target named |
| K CI generator | `tests/benchmarks/make_ci_workflow.py` | written |
| K procedural memory routing | `orchestrator.py` | agent order + iteration budget from procedural memory, **only when memory is on** |
| K "11 of 44" | `benchmark.md` | corrected (the old text said 3) |
| L held-out | `tests/heldout/PLAN.md`, `heldout.json`, `run_heldout.py` | template + runner; **refuses to run until `registered: true`** |
| Status log | `FINALE_PLAN.md` §10 | updated |
| INSTALLED.md | new artefact dirs listed; nothing installed |

### New tests
`tests/unit/test_policy.py`, `test_injection_scrub.py`, `test_sandbox.py` (the denial
tests are skipped off macOS), `test_repro.py`, `test_autonomy.py`, plus 3 auto-endpoint
tests appended to `test_dashboard.py`.

---

## 2. Not done (needs the Mac or more work)

1. **A: build + reach judge + fuzz + triage + repair for uploaded repos.** This is the
   largest gap. Suggested route: reuse `FuzzerManager` / `fuzz_pipeline`, run every
   execution under `KAVACH_SANDBOX=required`, and use `-print_coverage=1` for the
   reach judge.
2. **C: zlib CVE-2022-37434.** Needs a driver that calls `inflateGetHeader`,
   `setup.sh` entries for tags `v1.2.12` (vulnerable) and `v1.2.13` (fixed), and a
   generalised `_build` in `tests/real_cve_suite/manifest.py`, which only builds
   cJSON today. Validate it both ways before adding it. libpng still needs its CVE
   ID verified.
3. **G: CBMC bounded proof for cJSON `parse_string`.** Not started (2-hour go/no-go).
4. **B: the runs themselves.** Run cloud and local on the same targets, then compare.
5. **L: register the 4 libraries** (after verifying each), then run.
6. Workstream I needs the Juliet C suite downloaded.

---

## 3. Test on the Mac, in this order

Run from `ai_kavach_crs/` in the project's environment.

### 3.1 Unit tests (no API, no network)
```sh
python -m pytest tests/unit -q
```
Expected: all previous tests still pass, plus the new files. Watch for:
- `test_sandbox.py::test_macos_clang_build_works_inside_sandbox`. If it fails, the
  profile blocks something clang or xcrun needs (likely a cache write under
  `/var/folders/.../C/`). Add that path to `extra_writable` in `sandbox.plan` and
  record it.
- `test_sandbox.py::test_macos_denies_network` and `..._write_outside_workspace`:
  these are the denial evidence for F.
- `test_autonomy.py`: these exercise Tree-sitter field names. A failure here most
  likely means a node or field name differs in the installed tree-sitter-c version.

### 3.2 Policy gate does not reject previously passing fixes
```sh
python benchmark.py --suite synthetic --limit 10 --harden
```
Compare with the last full run. Any target that now fails with `failure_stage=policy`
means one of two things: the real fix lies outside the flagged function or exceeds 80
lines (a policy/target fact to report), or the rule is wrong (fix the rule). Do not
lower the bar silently. `KAVACH_POLICY=off` reproduces the old behaviour for comparison.
Also check the new run dir contains `manifest.json`, `tool-versions.json` and
`reproduce.sh`, then run `sh reports/benchmark_runs/<id>/reproduce.sh`.

### 3.3 Sandbox on the real gates
```sh
KAVACH_SANDBOX=required python benchmark.py --suite synthetic --only SYN-06-OFF-BY-ONE --harden
```
Expected: PASS, same as unsandboxed. If the build gate fails with
"Operation not permitted", extend the writable paths (see 3.1). Then measure the
overhead (time with and without) for the "lightweight" claim.

### 3.4 Verifier red-team
```sh
python -m tests.cheat_detector.run_redteam --json reports/special/redteam.json
```
Expected: the honest fix passes every layer. Each cheat is caught by at least one
layer. Publish whatever slips; do not edit the catalogue to hide it. Then check the
card on the dashboard.

### 3.5 Autonomous mode
```sh
python -m src.main --target tests/demo_vulns --mode auto --no-llm-harness --run-dir reports/auto_runs/demo
cat reports/auto_runs/demo/evidence.json
```
Expected: snapshot sha256, build plan `flat-c`, and one row per Semgrep finding, each
with a reason. Template harnesses land in `reports/auto_runs/demo/harnesses/`.
Compile one by hand with Homebrew clang
(`-fsanitize=fuzzer,address,undefined`) together with its source file, to check the
template output builds. Then repeat without `--no-llm-harness`.

### 3.6 Dashboard
```sh
python -m dashboard
```
Drop a small C repo, press Start analysis, watch the stage events, then press
"Show last result". Run the red-team from Special cases.

### 3.7 Comparison, CI generator, detection
```sh
python -m tests.benchmarks.compare_providers <cloud_run_id> <local_run_id> --md reports/compare.md
python -m tests.benchmarks.make_ci_workflow <run_id>
python -m tests.benchmarks.detection_eval --corpus <juliet_C_dir> --split eval --json reports/special/detection.json
```

---

## 4. Risks to check first

- **The policy gate is on by default** and changes benchmark behaviour (3.2).
- **The sandbox profile is untested** (3.1, 3.3). It is off by default, so nothing
  breaks unless it is switched on.
- **`Policy_Gate` is a new CSV column.** Any consumer that reads columns by position
  rather than by name needs checking. `reproduce.sh` uses columns 2 (ID) and
  6 (Status), which are unchanged.
- **Harness templates are text-generated C** and have never been compiled.
