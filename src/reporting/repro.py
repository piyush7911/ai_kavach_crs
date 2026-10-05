"""
AI Kavach CRS — reproducibility bundle for a run directory.

Every benchmark run directory gets three extra files:

  tool-versions.json  clang, Semgrep, CBMC, AFL++, Python, OS, chip, model ids,
                      seed, backend fingerprints, and the exact command line.
  reproduce.sh        re-runs ONE target with the run's flags into a fresh run
                      directory and compares its Status with the recorded one.
  manifest.json       sha256 + size of every file in the run directory
                      (written last, so it covers the two files above).

This is **hash-manifested**, not signed: it lets anyone detect that an artefact
changed after the run, and re-derive a verdict. It does not prove who produced it.
"""

import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

MANIFEST = "manifest.json"
TOOLS = "tool-versions.json"
REPRODUCE = "reproduce.sh"


def _version(cmd: list[str]) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception as e:                       # pragma: no cover - defensive
        return f"error: {e}"
    text = (out.stdout or out.stderr).strip().splitlines()
    return text[0].strip() if text else ""


def tool_versions(models: dict, seed, fingerprints, argv: list[str]) -> dict:
    llvm = "/opt/homebrew/opt/llvm/bin/clang"
    chip = None
    if platform.system() == "Darwin":
        chip = _version(["sysctl", "-n", "machdep.cpu.brand_string"])
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "argv": argv,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "chip": chip,
        "clang": _version(["clang", "--version"]),
        "clang_llvm": _version([llvm, "--version"]) if Path(llvm).exists() else None,
        "semgrep": _version(["semgrep", "--version"]),
        "cbmc": _version(["cbmc", "--version"]),
        "afl_fuzz": "present" if shutil.which("afl-fuzz") else None,
        "models": models,
        "seed": seed,
        "system_fingerprints": sorted(fingerprints or []),
        "openai_base_url": os.environ.get("OPENAI_BASE_URL", "default"),
        "sandbox": os.environ.get("KAVACH_SANDBOX", "off"),
        "policy": os.environ.get("KAVACH_POLICY", "on"),
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(run_dir: Path) -> dict:
    files = {}
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p.name != MANIFEST:
            rel = p.relative_to(run_dir).as_posix()
            files[rel] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}
    manifest = {"run_id": run_dir.name, "algorithm": "sha256", "files": files,
                "note": "hash-manifested, not signed"}
    (run_dir / MANIFEST).write_text(json.dumps(manifest, indent=2))
    return manifest


def verify_manifest(run_dir: Path) -> list[str]:
    """Paths whose content no longer matches the manifest (missing files included)."""
    manifest = json.loads((run_dir / MANIFEST).read_text())
    bad = []
    for rel, meta in manifest["files"].items():
        p = run_dir / rel
        if not p.exists() or sha256_file(p) != meta["sha256"]:
            bad.append(rel)
    return bad


def _flags_for_rerun(argv: list[str]) -> list[str]:
    """The run's own flags minus target selection and the event file."""
    out, skip = [], False
    for a in argv[1:]:
        if skip:
            skip = False
            continue
        if a in ("--only", "--limit", "--events"):
            skip = True
            continue
        if a.startswith(("--only=", "--limit=", "--events=")):
            continue
        out.append(a)
    return out


def reproduce_script(run_dir: Path, argv: list[str]) -> str:
    flags = " ".join(shlex.quote(a) for a in _flags_for_rerun(argv))
    run_id = run_dir.name
    return f"""#!/bin/sh
# Re-derive one verdict from run {run_id}.
#   sh reproduce.sh [TARGET_ID]     (default: the first target in per_target_results.csv)
# Re-runs that target with the run's flags and compares Status with the recorded one.
# Model output is not bit-for-bit deterministic even with a fixed seed; a different
# Status is reported, not hidden.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
CSV="$HERE/per_target_results.csv"
TARGET="${{1:-$(awk -F, 'NR==2 {{print $2; exit}}' "$CSV")}}"
RECORDED="$(awk -F, -v t="$TARGET" 'NR>1 && $2==t {{print $6; exit}}' "$CSV")"
[ -n "$RECORDED" ] || {{ echo "target $TARGET not in $CSV"; exit 2; }}
cd "$ROOT"
OUT="$(mktemp -d)"
BEFORE="$(ls -1dt reports/benchmark_runs/*/ 2>/dev/null | head -1)"
"${{PYTHON:-python3}}" benchmark.py {flags} --only "$TARGET" > "$OUT/log.txt" 2>&1 || true
NEW_DIR="$(ls -1dt reports/benchmark_runs/*/ | head -1)"
# A re-run that did not produce a NEW run directory did not run (wrong interpreter,
# missing dependency). Comparing against the original run would then "reproduce" it.
if [ "$NEW_DIR" = "$BEFORE" ]; then
  echo "re-run FAILED: no new run directory was produced. Last lines of the log:"; tail -5 "$OUT/log.txt"
  echo "(set PYTHON=/path/to/the/project/python and retry)"; exit 3
fi
NEW="$(awk -F, -v t="$TARGET" 'NR>1 && $2==t {{print $6; exit}}' "$NEW_DIR/per_target_results.csv")"
echo "target:   $TARGET"
echo "recorded: $RECORDED   (run {run_id})"
echo "re-run:   $NEW   ($NEW_DIR)"
if [ "$RECORDED" = "$NEW" ]; then echo "verdict reproduced"; exit 0; fi
echo "verdict DIFFERS"; exit 1
"""


def write_bundle(run_dir: Path, models: dict, seed, fingerprints, argv: Optional[list[str]] = None) -> dict:
    run_dir = Path(run_dir)
    argv = list(argv if argv is not None else sys.argv)
    (run_dir / TOOLS).write_text(json.dumps(tool_versions(models, seed, fingerprints, argv), indent=2))
    script = run_dir / REPRODUCE
    with open(script, "w", newline="\n") as f:
        f.write(reproduce_script(run_dir, argv))
    script.chmod(0o755)
    return write_manifest(run_dir)
