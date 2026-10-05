#!/usr/bin/env python3
"""
Run autonomous mode on each pre-registered held-out library.

    python -m tests.heldout.run_heldout [--no-llm-harness]

Reads tests/heldout/heldout.json. Refuses to run unless `registered` is true,
so the list cannot be chosen after seeing results. Each library is cloned at its
vulnerable ref into benchmark_workspace/heldout/<id>, auto mode runs on it, and
every finding's status and reason are collected into
reports/heldout/<timestamp>/heldout_report.json. Nothing is dropped: a library
that fails to clone or ingest appears with that error.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from src.autonomy.runner import AutoRunner                                       # noqa: E402

LIST = Path(__file__).resolve().parent / "heldout.json"
TREES = ROOT / "benchmark_workspace" / "heldout"


def checkout(lib: dict) -> Path:
    dest = TREES / lib["id"]
    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", lib["repo"], str(dest)], check=True, timeout=600)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", "--detach", lib["vulnerable_ref"]],
                   check=True, timeout=120)
    return dest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm-harness", action="store_true")
    args = ap.parse_args()
    spec = json.loads(LIST.read_text())
    if not spec.get("registered") or not spec.get("libraries"):
        print("held-out list is not registered yet; see tests/heldout/PLAN.md", file=sys.stderr)
        return 2
    llm = None
    if not args.no_llm_harness:
        from src.agent_orchestrator.llm_client import LLMClient
        llm = LLMClient()
    out_dir = ROOT / "reports" / "heldout" / time.strftime("%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True)
    rows = []
    for lib in spec["libraries"]:
        row = {"id": lib["id"], "defect": lib.get("defect", ""), "error": "", "summary": None,
               "unhandled": False}
        try:
            tree = checkout(lib)
            res = AutoRunner(out_dir / lib["id"], llm=llm).run(str(tree))
            row["error"] = res.error
            row["summary"] = res.to_dict()["summary"]
            row["findings"] = [{"id": f.id, "function": f.function, "status": f.status,
                                "reason": f.reason} for f in res.findings]
        except Exception as e:                   # clone/checkout or an escape from the runner
            row["error"] = f"{type(e).__name__}: {e}"
            row["unhandled"] = True
        rows.append(row)
        print(f"{lib['id']}: {row['error'] or row['summary']}", flush=True)
    report = {"generated_at": time.time(), "libraries": rows,
              "unhandled": [r["id"] for r in rows if r["unhandled"]]}
    (out_dir / "heldout_report.json").write_text(json.dumps(report, indent=2))
    print(f"report: {out_dir / 'heldout_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
