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

This is not hypothetical — it happened here. The original `SYN-03` harness
passed counts up to 2^28 while allocating only 100 records, and the original
`SYN-12` harness allowed lengths up to 4095 against a 256-byte buffer. Both
caused *false* hardening failures: re-fuzzing found "new crashes" in patches
that had correctly fixed the labelled vulnerability.

**Rule: size the buffer to the largest request the harness can generate.**

## Coverage: 8 of 20 `demo_vulns` targets have a harness

SYN-01, 02, 05, 06, 07, 11, 12, 16. Each was checked against the rule above:
the harness calls the vulnerable function directly with fuzz-controlled bytes,
and every count/index/length the harness passes is backed by memory the
harness actually allocated. SYN-01 is notable — its curated argv entrypoint
has **no** PoV (§ below), but calling the function directly from fuzz bytes
bypasses that limitation and finds the same bug argv cannot reach.

## Why the other 12 have none

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
| SYN-17 | Memory leak needs LeakSanitizer, unavailable on darwin-arm64. |
| SYN-18 | The overrun stays inside the enclosing `UserSession` struct; ASan redzones allocations, not fields within one struct, so this never trips a sanitizer here. |
| SYN-19 | `SAFE_FREE` nulls the pointer and the guard short-circuits — there is no live use-after-free to find. |
| SYN-20 | The uninitialised heap read needs MemorySanitizer; it also stays inside the allocation, so ASan sees nothing. |

If any of these become fuzzable on a different platform (Linux gets MSan/LSan;
see `driller_monitor.py` for the same story with concolic execution), add the
harness then — not before, per the rule above.
