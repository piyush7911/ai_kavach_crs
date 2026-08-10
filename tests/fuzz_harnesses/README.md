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

## Why SYN-03 has no harness

`process_events(uint32_t num_events, const char* event_data)` has no length for
`event_data`. Reaching its CWE-190 multiplication overflow requires
`num_events > UINT32_MAX / 32` (~1.3e8), which a fair harness would have to back
with roughly **4 GB** of source data. That is not practical in-process, so this
target is evaluated through its curated entrypoint only and carries no fuzz
harness. A harness that skipped the buffer requirement would only manufacture
unfixable crashes.
