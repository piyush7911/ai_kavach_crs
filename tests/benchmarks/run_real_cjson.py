"""
AI Kavach CRS — Real-world cJSON benchmark.

SUPERSEDED. The previous version of this script invented a CVE ID
("CVE-2026-67215-SIMULATED") and asked the agents to patch a line that had no
confirmed vulnerability, then reported the outcome as an NVD result. That was
not a real benchmark and has been removed.

The real-world cJSON targets now live in `tests/benchmarks/targets.py`. They are
actual Semgrep p/security-audit findings — no CVE is claimed — and each patch
must compile the whole library and keep cJSON's own upstream test suite passing
under AddressSanitizer + UndefinedBehaviorSanitizer.

Run them with:

    python benchmark.py --suite real_world
"""

import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/DaveGamble/cJSON.git"
REPO_PATH = Path("benchmark_workspace/cJSON")


def ensure_repo() -> Path:
    """Clone cJSON if it is not already present. Returns the repo path."""
    if not REPO_PATH.exists():
        REPO_PATH.parent.mkdir(parents=True, exist_ok=True)
        print(f"Cloning {REPO_URL} …")
        subprocess.run(["git", "clone", REPO_URL, str(REPO_PATH)], check=True)
    return REPO_PATH


if __name__ == "__main__":
    ensure_repo()
    print(__doc__)
    sys.exit(subprocess.call(
        [sys.executable, "benchmark.py", "--suite", "real_world"]
    ))
