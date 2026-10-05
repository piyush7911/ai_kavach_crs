"""
PoV pre-flight across every target in the project (no LLM, no cost).

For each target: compile it UNPATCHED, then run its proof-of-vulnerability. A PoV
that does not reproduce on the original cannot gate anything, so this is the
check that every later "PoV-proven" claim rests on.

    python -m dashboard.tasks.preflight [--events PATH]
"""

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.events import EventSink, NULL_SINK
from tests.benchmarks.targets import get_suite
from tests.standalone_support import preflight
from tests.vanguard_nightmare.manifest import VANGUARD_TARGETS
from tests.public_benchmarks_extension.manifest import PUBLIC_EXTENSION_TARGETS


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="")
    args = ap.parse_args()
    sink = EventSink(args.events) if args.events else NULL_SINK

    targets = list(get_suite("all")) + list(VANGUARD_TARGETS) + list(PUBLIC_EXTENSION_TARGETS)
    sink.emit("run_start", stage="preflight", status="info",
              message="PoV pre-flight", total=len(targets))
    sink.emit("suite_start", stage="suite", status="info", message="Pre-flight",
              suite="PoV pre-flight", total=len(targets))

    rows, started = [], time.time()
    for i, t in enumerate(targets, 1):
        sink.emit("target_start", stage="preflight", status="info", message=t.id,
                  suite="PoV pre-flight", id=t.id, index=i, total=len(targets))
        t0 = time.time()
        pf = preflight(t)
        if not pf.builds:
            state = "original_does_not_build"
        elif not pf.pov_configured:
            state = "no_pov"
        elif pf.pov_reproduces:
            state = "pov_valid"
        else:
            state = "pov_does_not_reproduce"
        row = {
            "id": t.id, "cwe": t.cwe_id, "state": state,
            "summary": pf.summary(),
            "no_pov_reason": getattr(t, "pov_na_reason", "") if state == "no_pov" else "",
            "regression_baseline_ok": pf.regression_baseline_ok,
            "seconds": round(time.time() - t0, 2),
        }
        rows.append(row)
        sink.emit("target_done", stage="preflight",
                  status="ok" if state in ("pov_valid", "no_pov") else "fail",
                  message=f"{t.id}: {state}", suite="PoV pre-flight", id=t.id,
                  result=state, seconds=row["seconds"], cost_usd=0)
        print(f"[{i}/{len(targets)}] {t.id}: {state}", flush=True)

    counts = {s: sum(1 for r in rows if r["state"] == s)
              for s in ("pov_valid", "no_pov", "pov_does_not_reproduce", "original_does_not_build")}
    payload = {"generated_at": time.time(), "seconds": round(time.time() - started, 1),
               "total": len(rows), "counts": counts, "rows": rows}
    out = PROJECT_ROOT / "reports" / "special" / "preflight.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    sink.emit("suite_done", stage="suite", status="ok", message="Pre-flight finished",
              suite="PoV pre-flight", patched=counts["pov_valid"], total=len(rows),
              seconds=payload["seconds"])
    sink.emit("run_done", stage="run", status="ok", message="pre-flight written")
    bad = counts["pov_does_not_reproduce"] + counts["original_does_not_build"]
    print(f"\nvalid PoVs: {counts['pov_valid']}  no PoV (documented): {counts['no_pov']}  "
          f"BROKEN: {bad}", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
