# Fuzz harnesses

Each `<TARGET-ID>.c` implements `LLVMFuzzerTestOneInput` for one benchmark
target. The same harness drives **libFuzzer** (in-process) and **AFL++**
(through `afl_driver.c`, which reads AFL's `@@` file and calls the same entry
point).

## Harnesses must respect the target's preconditions

Several of these C functions take a length or count but no bound for the buffer
they read from. A harness that passes a count larger than the buffer it supplies
makes the function **unfixable by contract**: no patch confined to that function
can prevent the resulting out-of-bounds read, so every candidate patch is
rejected and the agent is blamed for a defect in the harness.

This is not hypothetical — it happened three times here. The original `SYN-03`
harness passed counts up to 2^28 while allocating only 100 records, and the
original `SYN-12` harness allowed lengths up to 4095 against a 256-byte buffer.

The third case was subtler and is worth stating separately, because the
precondition it broke was not a size. The original `SYN-16` harness called
`print_user(uid, is_string)` with `is_string = 1` while populating the union's
*int* member. That asserts to the callee a fact the caller has made false, and
nothing inside `print_user` can detect it — the function was unfixable by
contract just as surely as an undersized buffer makes one unfixable. Re-fuzzing
duly reported a "new crash" for every correct patch. It also attacked a
different function from the one the target's `line_number` designated, so the
agent was being blamed for code outside the scope it was given.

`SYN-16` now targets `render_user()`, which creates and consumes the confusion
itself, so the labelled line, the PoV path and the harness all address one
function that a patch can actually fix.

All three caused *false* hardening failures: re-fuzzing found "new crashes" in
patches that had correctly fixed the labelled vulnerability.

**Second rule, from the SYN-16 case: the harness must exercise the same function
the target's `line_number` points at.** Falsification scope has to match repair
scope, or a correct patch is judged against code it was never shown.

**Rule: size the buffer to the largest request the harness can generate.**

## Coverage: 9 of 20 `demo_vulns` targets have a harness

SYN-01, 02, 05, 06, 07, 11, 12, 16, 18. Each was checked against the rule above:
the harness calls the vulnerable function directly with fuzz-controlled bytes,
and every count/index/length the harness passes is backed by memory the
harness actually allocated. Two are notable, for the same reason: the curated entrypoint's limitation is a
fact about *that call site*, not about the function.

- **SYN-01** has no argv PoV — the version field `0x0100` contains a NUL, so no
  argv string satisfies the header guards. Calling the function directly from
  fuzz bytes reaches the same bug argv cannot.
- **SYN-18** has no argv PoV either: `main()` passes `key_len = 100` against a
  100-byte `UserSession`, so the overrun stays inside the object and ASan
  redzones allocations rather than fields. But `update_key()` takes an unbounded
  `key_len` from its caller, and a caller passing more than `sizeof(UserSession)`
  runs off the end of the object itself — which ASan does see. Measured: the
  original crashes at `18_ast_deep_struct.c:13`, and a patch clamping the copy
  to `sizeof(secret_key)` survives 25M runs.

## Why the other 11 have none

Manufacturing a harness for these would either produce a flaky, non-deterministic
oracle or a "crash" that isn't the documented weakness. Each reason below matches
the `pov_na_reason` already recorded for the same target in
`tests/benchmarks/targets.py` — the fuzz suite and the curated suite agree on
what is and isn't provable here.

| Target | Why no harness |
|---|---|
| SYN-03 | `process_events` has no length field for `event_data`; reaching the CWE-190 overflow needs `num_events > UINT32_MAX/32` (~1.3e8), which would need ~4 GB of backing data to fuzz honestly. |
| SYN-04 | Reaching the truncation needs an input `> UINT32_MAX` bytes — not practical in-process. |
| SYN-08 | Traversal only manifests if `/var/www/html/users` exists; on this host `fopen()` fails identically for benign and malicious paths, so there is no crash oracle to fuzz toward. |
| SYN-09 | `system()` command injection has no memory-safety crash signature; ASan/UBSan cannot observe "a shell command ran". |
| SYN-10 | The 800 KB allocation this target relies on never fails, so the missing NULL check never manifests as a crash. |
| SYN-13 | TOCTOU requires a concurrent attacker racing the check and the use; not reproducible from a single fuzz iteration. |
| SYN-14 | Detecting the uninitialised read needs MemorySanitizer (Linux/x86-64 only); under ASan the read is UB but not reliably a crash. |
| SYN-15 | Hardcoded secret has no runtime behaviour to fuzz toward — statically observable only. |
| SYN-17 | LeakSanitizer *is* available here (Homebrew LLVM's runtime; Apple's is not), and SYN-17 now has a curated leak PoV. It still gets no fuzz harness: under libFuzzer, LSan attributes libFuzzer's own allocations to the run — a correctly patched build reports "56 byte(s) leaked" from `FuzzerMain.cpp` — so the oracle would fail correct patches. |
| SYN-19 | `SAFE_FREE` nulls the pointer and the guard short-circuits — there is no live use-after-free to find. |
| SYN-20 | The uninitialised heap read needs MemorySanitizer; it also stays inside the allocation, so ASan sees nothing. |

If any of these become fuzzable on a different platform (Linux gets MSan/LSan;
see `driller_monitor.py` for the same story with concolic execution), add the
harness then — not before, per the rule above.
