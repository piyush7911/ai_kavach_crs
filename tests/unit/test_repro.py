"""Reproducibility bundle: manifest covers everything and detects tampering."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.reporting import repro


def test_bundle_files_and_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(repro, "_version", lambda cmd: "test-version")
    run = tmp_path / "20260101_000000"
    run.mkdir()
    (run / "per_target_results.csv").write_text("Suite,ID,CWE,Complexity,File,Status\nS,T1,C,e,f.c,patched\n")
    manifest = repro.write_bundle(run, models={"alpha": "m"}, seed=1337, fingerprints={"fp"},
                                  argv=["benchmark.py", "--suite", "synthetic", "--only", "T1",
                                        "--events", "e.jsonl", "--harden"])
    files = manifest["files"]
    assert {"per_target_results.csv", "tool-versions.json", "reproduce.sh"} <= set(files)
    tools = json.loads((run / "tool-versions.json").read_text())
    assert tools["seed"] == 1337 and tools["system_fingerprints"] == ["fp"]
    script = (run / "reproduce.sh").read_bytes()
    assert b"\r\n" not in script
    assert b"--harden" in script and b"--events" not in script
    assert repro.verify_manifest(run) == []
    (run / "per_target_results.csv").write_text("tampered")
    assert repro.verify_manifest(run) == ["per_target_results.csv"]


def test_rerun_flags_drop_selection():
    assert repro._flags_for_rerun(["b.py", "--suite", "all", "--limit", "3", "--only=X", "--formal"]) == \
        ["--suite", "all", "--formal"]


def test_reproduce_fails_when_the_rerun_did_not_run(tmp_path, monkeypatch):
    """A re-run that produced no new run directory must not read as 'verdict reproduced'."""
    import subprocess
    monkeypatch.setattr(repro, "_version", lambda cmd: "test-version")
    run = tmp_path / "reports" / "benchmark_runs" / "20260101_000000"
    run.mkdir(parents=True)
    (run / "per_target_results.csv").write_text("Suite,ID,CWE,Complexity,File,Status\nS,T1,C,e,f.c,patched\n")
    repro.write_bundle(run, models={}, seed=1, fingerprints=set(),
                       argv=["benchmark.py", "--suite", "synthetic", "--harden"])
    # no benchmark.py in tmp_path, so the re-run fails immediately
    r = subprocess.run(["sh", str(run / "reproduce.sh"), "T1"], capture_output=True, text=True)
    assert r.returncode == 3 and "reproduced" not in r.stdout.replace("not", "")
