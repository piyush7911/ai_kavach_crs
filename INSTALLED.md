# AI Kavach CRS — Installation & Dependency Tracker
# Everything installed for this project, so it can be removed cleanly later.
# Last updated: 2026-08-07

## Conda Environment
- **Name:** `ai_kavach`
- **Python:** 3.11
- **Interpreter:** `/opt/homebrew/Caskroom/miniconda/base/envs/ai_kavach/bin/python`
- **Create:** `conda create -n ai_kavach python=3.11 -y`
- **Remove:** `conda env remove -n ai_kavach -y`

## Python Packages (pip, inside the conda env)

| Package | Purpose | Status | Uninstall |
|---|---|---|---|
| openai | OpenAI API client | in use | `pip uninstall openai` |
| python-dotenv | Load `.env` | in use | `pip uninstall python-dotenv` |
| tree-sitter | AST parsing engine | in use | `pip uninstall tree-sitter` |
| tree-sitter-c | C grammar | in use | `pip uninstall tree-sitter-c` |
| tree-sitter-cpp | C++ grammar | in use | `pip uninstall tree-sitter-cpp` |
| pydantic | Data validation | in use | `pip uninstall pydantic` |
| rich | Terminal output | in use | `pip uninstall rich` |
| pytest | Unit tests | in use | `pip uninstall pytest` |
| semgrep | Static analysis → SARIF | in use (v1.172.0) | `pip uninstall semgrep` |
| **angr** | Symbolic execution for Driller | **added 2026-08-07** | `pip uninstall angr` |
| ~~langgraph~~ | — | **NOT used**; commented out of requirements.txt | `pip uninstall langgraph` |
| ~~langchain-openai~~ | — | **NOT used**; commented out | `pip uninstall langchain-openai` |
| ~~langchain-core~~ | — | **NOT used**; commented out | `pip uninstall langchain-core` |

`angr` pulls a large dependency tree (claripy, cle, pyvex, archinfo, unicorn, z3-solver,
capstone, …). Removing it cleanly is easiest by recreating the conda env.

## System Tools (Homebrew)

| Tool | Purpose | Status | Install | Uninstall |
|---|---|---|---|---|
| **afl++** | Coverage-guided fuzzing (`afl-fuzz`, `afl-clang-fast`) | **added 2026-08-07**, v5.02c | `brew install afl++` | `brew uninstall afl++` |
| **llvm** | Pulled in as an afl++ dependency; its clang provides the **libFuzzer** runtime that Apple's clang lacks | **added 2026-08-07**, v22.1.8 | `brew install llvm` | `brew uninstall llvm` |
| clang (Apple) | Compiler + ASan/UBSan for the DRV gates | pre-existing | Xcode CLT | n/a |
| patch, git | Patch application, repo cloning | pre-existing | — | n/a |
| CASR | Crash triage | **NOT installed** — needs Rust/cargo, which is absent. A native ASan triage engine (`src/analysis_engine/crash_triage.py`) is used instead and is auto-superseded by CASR if it ever appears on PATH. | `cargo install casr` | `cargo uninstall casr` |
| cmake | Not needed — cJSON is built directly with clang | not installed | — | — |

## Platform notes discovered during setup

- **libFuzzer:** Apple's `/usr/bin/clang` does not ship `libclang_rt.fuzzer_osx.a`.
  Homebrew LLVM does. `FuzzerManager.libfuzzer_clang()` auto-detects
  `/opt/homebrew/opt/llvm/bin/clang`.
- **AFL++ on macOS:** `afl-fuzz` aborts with `shmget() failed` under the default
  SysV shared-memory limits (`kern.sysv.shmall` = 1024 pages). `FuzzerManager`
  sets `AFL_MAP_SIZE=65536` automatically, which makes it work without root.
  For full-size maps run `sudo afl-system-config`.
- **angr on this host:** installs and imports fine (v9.2.213, unicorn support
  disabled), but its known-answer self-test **fails on arm64 Mach-O** — it reaches
  the target branch yet cannot tie the symbolic input to the comparison.
  `DrillerEngine.self_test()` detects this and disables concolic reporting, so no
  meaningless "solved" inputs are ever produced. On x86-64 Linux the same code path
  self-tests successfully.

## Artifacts written under the project (safe to delete)

```
benchmark_workspace/fuzzing/      # fuzz builds, corpora, crash artifacts
benchmark_workspace/triage/       # triage scratch
benchmark_workspace/driller/      # concolic scratch
benchmark_workspace/cJSON/        # cloned upstream repo
reports/benchmark_runs/           # measured benchmark output
```

## Full Cleanup

```bash
# 1. Python side (removes angr and every pip package)
conda env remove -n ai_kavach -y

# 2. Fuzzing toolchain added for this project
brew uninstall afl++
brew uninstall llvm          # only if nothing else needs it

# 3. Generated artifacts
rm -rf "/Users/piyush/Desktop/cyber hackathon/ai_kavach_crs/benchmark_workspace"
rm -rf "/Users/piyush/Desktop/cyber hackathon/ai_kavach_crs/reports"

# 4. Project directory (optional)
# rm -rf "/Users/piyush/Desktop/cyber hackathon/ai_kavach_crs"
```
