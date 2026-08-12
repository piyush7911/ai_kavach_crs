# Real-CVE suite

Published CVEs in **unmodified upstream source**. Every other corpus in this
project is code we wrote; this one is not. Each tree is upstream cJSON checked
out at the commit immediately *before* the security fix landed, so the defect is
the one that actually shipped.

Self-contained and re-runnable: everything the suite needs is in this folder.

```
setup.sh          materialises the vulnerable trees (git worktrees, idempotent)
drivers/          one C driver per CVE
manifest.py       target definitions + verification contracts
run_real_cve.py   standalone runner
```

## Running it

```bash
sh tests/real_cve_suite/setup.sh              # once; re-run any time
python -m tests.real_cve_suite.run_real_cve   # standalone
python benchmark.py --suite real_cve --harden # via the main harness
```

The trees are **not vendored** — `setup.sh` clones cJSON and creates a worktree
per CVE. Targets whose tree is missing are omitted from the suite rather than
reported as failures, so a fresh checkout degrades to "not evaluated".

## Targets

Each was validated in **both directions** before being added: the PoV reproduces
on the vulnerable commit, and the upstream fix resolves it.

### CVE-2019-11835 — `cJSON_Minify` out-of-bounds read

* **Vulnerable at:** `v1.7.10`; fixed in 1.7.11
* **Defect:** on an unterminated `/*`, the scan loop halts at the NUL terminator
  and the following `json += 2` steps **past** it, so the enclosing
  `while (*json)` reads out of bounds.
* **PoV:** `'/*'` → `heap-buffer-overflow READ at cJSON.c:2642 in cJSON_Minify`
* **Regression:** `'{ "a" : 1 }'` → `minified: {"a":1}`

### CVE-2019-11834 — `parse_string` heap over-read

* **Vulnerable at:** `b537ca7`; fixed by `a167d9e`
* **Defect:** the loop evaluated `*input_end != '"'` **before** the bounds check.
  C's `&&` is ordered, so the dereference happens first and reads one byte past
  the allocation on an unterminated string literal. The upstream fix simply
  swaps the two operands.
* **PoV:** `'"abc'` → `heap-buffer-overflow READ at cJSON.c:660 in parse_string`
* **Regression:** `'{"a":1}'` → `parsed: ok`

This one is genuinely hard: the buggy line *looks* correct. Nothing is missing —
two conditions are simply in the wrong order.

## Adding another CVE

1. Find the upstream fix commit: `git -C benchmark_workspace/cJSON_cve log --oneline -i --grep=overflow`
2. Take its **parent** — that is the vulnerable state.
3. Add a worktree line to `setup.sh` and an entry to `_CANDIDATES` in `manifest.py`.
4. Write a driver in `drivers/` that reaches the function from `main`.
5. **Verify both directions before committing to it**: the PoV must fail on the
   vulnerable commit *and* pass on the fix. A PoV that does not reproduce proves
   nothing, and the pre-flight will disable it.

Quote arguments with `shlex.quote` — JSON payloads contain double quotes, and
wrapping them in double quotes lets the shell collapse `{"a":1}` into `{a:1}`.
