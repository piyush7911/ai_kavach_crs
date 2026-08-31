"""
AI Kavach CRS — NIST Juliet benchmark harness.

SUPERSEDED. Do not use. Kept only so the reason is on record.

The previous version of this file walked a Juliet directory and ran the pipeline
on each CWE folder. It could not honestly report anything, for two reasons:

  * It passed no `build_command`, `pov_command` or `test_command`, so every
    verification gate was SKIPPED. "Patched" would have meant only "the model
    emitted a parseable diff" — nothing was compiled, no exploit was replayed,
    no regression was checked.
  * Its own comment read: *"Mocking CASR finding the crash since Semgrep misses
    Juliet's convoluted pointer arithmetic."* The crash finding that located the
    bug was synthesised rather than observed. A result derived from a mocked
    detection is not a detection result.

Where the real work lives
-------------------------
The Juliet targets are in `tests/benchmarks/targets.py` (`JULIET`), carrying a
real verification contract each: a build command with ASan + UBSan under
`-fno-sanitize-recover=all`, a pre-flighted PoV that is proven to reproduce on
the unpatched binary, and a regression command. They are scored by
`benchmark.py`, which reports every gate as PASS / FAIL / SKIPPED with a reason
and never counts a SKIPPED gate as a pass.

Run them with:

    python benchmark.py --suite juliet --harden

To add more Juliet cases, extend `JULIET` in `tests/benchmarks/targets.py` with
the same contract fields; a target with no reproducible PoV must carry a written
`pov_na_reason` rather than silently scoring as verified.
"""

import sys

if __name__ == "__main__":
    print(__doc__)
    sys.exit(1)
