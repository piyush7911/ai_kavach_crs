"""
Read measured results from run artefacts on disk.

Nothing in this module produces a number. It parses what `benchmark.py` and the
standalone suites already wrote, and refuses to invent a figure when the data is
absent: no runs means an empty result, not a placeholder.
"""

import csv
import json
import math
import re
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = PROJECT_ROOT / "reports" / "benchmark_runs"
REPORTS_DIR = PROJECT_ROOT / "reports"
SPECIAL_DIR = REPORTS_DIR / "special"

STANDALONE = {
    "Project Vanguard-0": "vanguard_nightmare_report.md",
    "CVE-inspired extension": "public_benchmarks_report.md",
}


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. Kept identical to benchmark.wilson_interval (a test pins that)."""
    if n == 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rate_label(successes: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson_interval(successes, n)
    return f"{successes / n * 100:.1f}% [{lo * 100:.1f}, {hi * 100:.1f}]"


# -- benchmark runs -----------------------------------------------------------

def list_runs() -> list[dict]:
    """All benchmark runs on disk, newest first, with a one-line description."""
    if not RUNS_DIR.exists():
        return []
    out = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        f = d / "benchmark_summary.json"
        if not f.exists():
            continue
        try:
            s = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        t = s.get("totals", {})
        out.append({
            "id": d.name,
            "timestamp": s.get("timestamp", ""),
            "targets": t.get("targets_attempted", 0),
            "patched": t.get("patched_all_configured_gates", 0),
            "mode": s.get("mode", ""),
            "suites": [x.get("Label") for x in s.get("suites", [])],
        })
    return out


# A full evaluation covers dozens of targets; runs of 1-4 are spot checks and
# re-runs of failures. The headline must not silently become a spot check just
# because it is the newest file on disk.
FULL_RUN_MIN_TARGETS = 30


def default_run_id(runs: list[dict]) -> Optional[str]:
    """Newest run that looks like a full evaluation; else the newest run; else None."""
    for r in runs:                                   # list_runs() is newest first
        if r["targets"] >= FULL_RUN_MIN_TARGETS:
            return r["id"]
    return runs[0]["id"] if runs else None


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def run_detail(run_id: str) -> Optional[dict]:
    """Full detail for one run. `run_id` is validated against the directory listing."""
    if not re.fullmatch(r"[0-9_]+", run_id):
        return None
    d = RUNS_DIR / run_id
    f = d / "benchmark_summary.json"
    if not f.exists():
        return None
    summary = json.loads(f.read_text())
    return {
        "id": run_id,
        "summary": summary,
        "targets": _read_csv(d / "per_target_results.csv"),
        "preflight": _read_csv(d / "preflight_pov_validation.csv"),
    }


def hardening_counts(rows: list[dict]) -> dict:
    """
    The three numbers, never one: attacked-and-held, falsified, and not attacked.
    A patch no check could attack has not survived anything and is not a survivor.
    """
    patched = [r for r in rows if r.get("Status") == "patched" or r.get("Status") == "unresolved_hardening"]
    held = [r for r in rows if r.get("Hardening_Survived") == "True"]
    falsified = [r for r in rows if r.get("Status") == "unresolved_hardening"]
    attempted = [r for r in rows if r.get("Hardening")]
    not_attacked = [r for r in attempted
                    if r.get("Hardening_Survived") != "True" and r.get("Status") != "unresolved_hardening"]
    return {"attacked_and_held": len(held), "falsified": len(falsified),
            "not_attacked": len(not_attacked), "patched_total": len(patched)}


def parse_standalone(filename: str) -> dict:
    """Totals from a standalone suite report's summary table (rows, not an aggregate line)."""
    path = REPORTS_DIR / filename
    if not path.exists():
        return {"present": False}
    text = path.read_text()
    rows = [ln for ln in text.splitlines()
            if re.match(r"\|\s*\*\*[A-Z0-9][A-Z0-9-]+\*\*\s*\|", ln)]
    cost = re.search(r"Execution Cost:\*{0,2}\s*\$([0-9.]+)", text)
    secs = re.search(r"Total Evaluation Time:\*{0,2}\s*([0-9.]+)s", text)
    return {
        "present": True,
        "passed": sum(1 for r in rows if "**PATCHED**" in r),
        "total": len(rows),
        "survived": sum(1 for r in rows if "SURVIVED" in r),
        "cost": float(cost.group(1)) if cost else 0.0,
        "seconds": float(secs.group(1)) if secs else 0.0,
        "modified": path.stat().st_mtime,
    }


def headline(run_id: Optional[str] = None) -> dict:
    """
    The headline for one run, plus the standalone suites found on disk.

    The standalone reports are NOT tied to a run id, so they are reported with
    their own modification times and the caller can see when they were produced.
    If the newest run has no standalone companions the numbers simply cover the
    main harness, and `covers` says so.
    """
    runs = list_runs()
    if not runs:
        return {"empty": True, "message": "No benchmark runs on disk yet."}
    run_id = run_id or default_run_id(runs)
    detail = run_detail(run_id)
    if not detail:
        return {"empty": True, "message": f"Run {run_id} not found."}

    s = detail["summary"]
    t = s["totals"]
    llm = s.get("llm_usage", {})
    res = s.get("resource_usage", {})
    rows = detail["targets"]
    hard = hardening_counts(rows)

    suites = [{
        "label": x.get("Label"), "attempted": x.get("Targets_Attempted"),
        "patched": x.get("Patched_All_Gates"), "rate": x.get("Success_Rate"),
        "ci": x.get("Success_Rate_95CI"),
        "pov": f"{x.get('PoV_Verified_Fixes')}/{x.get('Targets_With_Reproducible_PoV')}",
        "seconds": x.get("Duration_s"),
    } for x in s.get("suites", [])]

    extras = {name: parse_standalone(fn) for name, fn in STANDALONE.items()}
    present = {k: v for k, v in extras.items() if v.get("present")}

    attempted = t["targets_attempted"] + sum(v["total"] for v in present.values())
    patched = t["patched_all_configured_gates"] + sum(v["passed"] for v in present.values())
    pov_gated = t["targets_with_reproducible_pov"] + sum(v["total"] for v in present.values())
    pov_proven = t["pov_verified_fixes"] + sum(v["passed"] for v in present.values())

    patch_sizes = [int(r["Patch_Lines"]) for r in rows
                   if r.get("Status") == "patched" and r.get("Patch_Lines") not in ("", None, "0")]

    return {
        "empty": False,
        "run_id": run_id,
        "timestamp": s.get("timestamp"),
        "mode": s.get("mode"),
        "models": s.get("models"),
        "platform": s.get("platform"),
        "main": {"attempted": t["targets_attempted"], "patched": t["patched_all_configured_gates"],
                 "rate": rate_label(t["patched_all_configured_gates"], t["targets_attempted"])},
        "combined": {
            "covers": ["main harness"] + [k for k in present],
            "attempted": attempted, "patched": patched,
            "rate": rate_label(patched, attempted),
            "pov_proven": pov_proven, "pov_gated": pov_gated,
            "pov_rate": rate_label(pov_proven, pov_gated),
        },
        "standalone": extras,
        "hardening": {**hard,
                      # attacked-and-held across everything this headline covers: the
                      # main run's survivors plus the standalone suites' survivors
                      "held_combined": hard["attacked_and_held"] + sum(v.get("survived", 0) for v in present.values())},
        "suites": suites,
        # Cost and time cover the main harness PLUS the standalone suites found on
        # disk, matching how the headline counts targets. Tokens and API calls stay
        # main-harness-only because the standalone reports do not record them.
        "cost_usd": round((llm.get("estimated_cost_usd") or 0) + sum(v.get("cost", 0) for v in present.values()), 4),
        "main_cost_usd": llm.get("estimated_cost_usd"),
        "api_calls": llm.get("api_calls"),
        "tokens_in": llm.get("input_tokens"),
        "tokens_out": llm.get("output_tokens"),
        "peak_rss_mb": res.get("peak_rss_mb_orchestrator_process"),
        "seconds": round(sum(x.get("Duration_s") or 0 for x in s.get("suites", []))
                         + sum(v.get("seconds", 0) for v in present.values()), 1),
        "mean_patch_lines": round(sum(patch_sizes) / len(patch_sizes), 1) if patch_sizes else None,
        "formal_proven": sum(1 for r in rows if r.get("Formal") == "proven"),
        "not_measured": s.get("not_measured", []),
    }


# -- special-case results (written by the special jobs) -------------------------

def special_result(name: str) -> Optional[dict]:
    """A special job's last result, or None. `name` is whitelisted."""
    if name not in {"cheat_detector", "preflight", "modelcheck", "redteam"}:
        return None
    path = SPECIAL_DIR / f"{name}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    data["_modified"] = path.stat().st_mtime
    data["_age_s"] = round(time.time() - path.stat().st_mtime)
    return data
