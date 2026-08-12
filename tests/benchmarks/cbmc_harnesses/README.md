# CBMC proof harnesses

One harness per target that can be formally verified. Each declares the
vulnerable function, makes its inputs nondeterministic, and lets CBMC prove
that no safety property is violated for **any** of them within the unwind bound.

## Why a harness rather than `main()`

Verifying `main()` with unconstrained `argv` makes CBMC report failures inside
its own models of libc — `strtol` dereferences, unwinding assertions — and those
failures persist on a *correctly patched* file. They are therefore useless as a
signal. Measured, not assumed: the original and the fixed version of
`11_oob_multidim_array.c` both report `VERIFICATION FAILED` when run over `main`.

With a harness over `read_matrix(row, col)` the same pair separates cleanly:
the original fails on `array 'matrix'[] upper bound`, the patched version
verifies.

## Preconditions

The same rule as the fuzz harnesses: **do not hand the function inputs its
contract forbids.** Use `__CPROVER_assume()` to state a genuine precondition
(e.g. a buffer really does hold `n` elements). Omitting a real precondition
manufactures violations no patch can fix; adding a fake one hides real bugs.
Assume only what the caller in the program actually guarantees.

## Why SYN-03 has no harness

`process_events(num_events, event_data)` requires `event_data` to hold
`num_events` records. Its CWE-190 multiplication overflow needs
`num_events > UINT32_MAX / 32` (~1.3e8), which a precondition-respecting harness
would have to back with roughly 4 GB.

Assuming a realistic bound (`n <= 8`) makes CBMC report **PROVEN** — truthfully,
because no overflow can occur under that assumption, but the result says nothing
about the vulnerability. That is a vacuous proof, and reporting it as formal
verification of the bug would be worse than reporting nothing. Dropping the
precondition instead manufactures violations no patch could fix.

Both directions are wrong, so this target is evaluated dynamically only — the
same conclusion its fuzz harness reached.
