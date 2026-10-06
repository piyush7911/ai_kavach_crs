# Python repair — BUILT and PROVEN (Track 1); integration notes (Track 2)

> UPDATE: the autonomous loop is now built and proven. `src/pyauto/repair.py` + `runner.py` run
> the full find->fix->prove on VAmPI with codegemma:7b (proven, first attempt). What is left is
> folding it into the unified engine / dashboard / `fix` command and adding a Python policy gate.

Goal: a full Python find -> fix -> prove loop, the counterpart of `src/jsauto`'s repair.

## Built and proven (Track 1)
- **Detection** `src/pyauto/static.py` + `config/semgrep/kavach_py.yaml`: generic Python/Flask rules,
  offline, mapped to the enclosing function with tree-sitter-python, emitting the shared `Finding`.
  On VAmPI: 4 bugs in 2 s.
- **Patch splicer** `src/pyauto/patch.py`: `find_function_span`, `replace_function` (whole-function
  replacement by tree-sitter-python byte range, indentation-matched), `parse_errors` (syntax gate).
  Tested; a spliced VAmPI fix parses as valid Python.
- **Verification** is already language-neutral: the runner's HTTP oracles (replay/regress/harden +
  the differential/idor/access-control metamorphic oracles) confirm Python bugs via the per-app
  adapter (`benchmarks/apps/vampi.json`). Proven BOTH directions on VAmPI mass-assignment: vulnerable
  -> exploitable (200), spliced fix -> denied (401).

So detect, apply, and prove all work for Python. The LLM is already general.

## Wiring left (Track 2 — mirror src/jsauto)
1. **Python repair prompts / context** (`pyauto/context.py`): show the model the function to fix
   (`replace_function` target), the class guidance (reuse `config/js_fix_guidance.json` — it is
   language-neutral advice; add py examples if useful), and the chain. Ask for the whole function.
2. **Parse + policy gate for Python**: `parse_errors` is the apply gate; add a Python policy
   (single function, no new imports of os/subprocess/eval, bounded size) alongside the JS one.
3. **Repair loop**: reuse `src/jsauto/repair.py`'s loop shape — it is language-neutral except the
   splicer/parse; swap in `pyauto.patch`. The gates are the same `Gates` (replay/regress/harden)
   pointed at the Python app via the adapter.
4. **A managed adapter for the target** so a PATCHED copy is run per attempt (the gate needs to
   restart the app with the patch). VAmPI: rebuild/run the Docker image, or run natively under
   Python 3.11 on a free port. External mode (current) only confirms the unpatched app.

Everything above `#4` is a thin mirror of the JS repair; `#4` (run a patched Python app per attempt)
is the one genuinely new integration.
