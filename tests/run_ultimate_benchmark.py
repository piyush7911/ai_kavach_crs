"""
AI Kavach CRS — Master benchmark entry point.

SUPERSEDED. The previous version of this script ran all 20 targets with no
build, PoV, or regression command configured, which meant "patched" only ever
meant "the model emitted a parseable diff" — yet the generated audit report
printed "Build Check: PASS / PoV Check: PASS / Regression Check: PASS" for
every one of them. It also carried a fabricated CVE identifier for cJSON.

Scoring now runs through `benchmark.py`, which:
  * pre-flights every target (compiles it unpatched and proves the PoV
    reproduces before that PoV is allowed to gate anything),
  * compiles each candidate patch under ASan + UBSan,
  * replays the PoV and a benign regression input against the PATCHED binary,
  * reports every gate as PASS / FAIL / SKIPPED with the reason.

Run the full gauntlet (all curated suites plus fuzz-discovery, parallel ensemble):

    python benchmark.py --suite all --fuzz
"""

import subprocess
import sys

if __name__ == "__main__":
    print(__doc__)
    sys.exit(subprocess.call(
        [sys.executable, "benchmark.py", "--suite", "all", "--fuzz"]
    ))
