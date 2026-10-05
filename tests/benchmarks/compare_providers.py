#!/usr/bin/env python3
"""
Side-by-side table of two measured benchmark runs (e.g. cloud vs local model).

    python -m tests.benchmarks.compare_providers RUN_A RUN_B [--md out.md] [--json out.json]

RUN_A / RUN_B are run ids under reports/benchmark_runs/ (or paths). Every value
is read from those run directories; nothing is estimated. Targets present in
only one run are listed, and the per-target comparison covers the intersection
only, so a smaller local run is never compared against a larger cloud one as if
they were the same population.

"Output tokens per wall-second" is total output tokens over the summed
per-target wall time. It includes compile and gate time, so it is NOT the
model's generation speed; the model check on the dashboard measures that.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

RUNS = Path(__file__).resolve().parent.parent.parent / "reports" / "benchmark_runs"


def load(run: str) -> dict:
    d = Path(run) if Path(run).is_dir() else RUNS / run
    summary = json.loads((d / "benchmark_summary.json").read_text())
    with open(d / "per_target_results.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    return {"dir": d, "summary": summary, "rows": {r["ID"]: r for r in rows}}


def _f(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def metrics(run: dict, ids: set) -> dict:
    rows = [r for i, r in run["rows"].items() if i in ids]
    s = run["summary"]
    seconds = sum(_f(r.get("Seconds")) for r in rows)
    out_tokens = s["llm_usage"]["output_tokens"]
    patched = sum(1 for r in rows if r["Status"] == "patched")
    pov = [r for r in rows if r.get("PoV_Available") == "True"]
    return {
        "run_id": run["dir"].name,
        "models": sorted(set(s["models"].values())),
        "targets": len(rows),
        "patched_all_gates": patched,
        "pass_rate": f"{100 * patched / len(rows):.1f}%" if rows else "n/a",
        "pov_proven": f"{sum(1 for r in pov if r['Status'] == 'patched' and r['PoV_Gate'] == 'pass')}/{len(pov)}",
        "mean_seconds_per_target": round(seconds / len(rows), 1) if rows else None,
        # Token and cost totals exist per run, not per target: they are only
        # comparable when the run contains exactly the compared targets.
        "usage_scope": "compared targets" if len(run["rows"]) == len(rows) else "WHOLE RUN (larger set)",
        "output_tokens": out_tokens,
        "output_tokens_per_wall_second": (round(out_tokens / seconds, 1)
                                          if seconds and len(run["rows"]) == len(rows) else None),
        "cost_usd": s["llm_usage"]["estimated_cost_usd"],
        "unpriced_tokens": s["llm_usage"].get("unpriced_tokens", 0),
        "peak_rss_mb_harness": s.get("resource_usage", {}).get("peak_rss_mb_orchestrator_process"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_a")
    ap.add_argument("run_b")
    ap.add_argument("--md", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    a, b = load(args.run_a), load(args.run_b)
    common = set(a["rows"]) & set(b["rows"])
    if not common:
        print("the two runs share no targets; nothing to compare", file=sys.stderr)
        return 2
    ma, mb = metrics(a, common), metrics(b, common)
    per_target = [{"id": i, "a": a["rows"][i]["Status"], "b": b["rows"][i]["Status"],
                   "a_seconds": a["rows"][i].get("Seconds"), "b_seconds": b["rows"][i].get("Seconds")}
                  for i in sorted(common)]
    only = {"only_in_a": sorted(set(a["rows"]) - common), "only_in_b": sorted(set(b["rows"]) - common)}

    lines = [f"| Metric | {ma['run_id']} | {mb['run_id']} |", "|---|---:|---:|"]
    for k in ma:
        if k == "run_id":
            continue
        lines.append(f"| {k} | {ma[k]} | {mb[k]} |")
    lines += ["", f"Compared over the {len(common)} targets present in both runs.",
              "Local runs are priced at $0 only when the model is unpriced; unpriced tokens are shown.",
              "Peak RSS is the harness process only; a local model's own memory is reported by the "
              "model check (Ollama /api/ps), not here.", "",
              "| Target | A | B | A s | B s |", "|---|---|---|---:|---:|"]
    lines += [f"| {r['id']} | {r['a']} | {r['b']} | {r['a_seconds']} | {r['b_seconds']} |" for r in per_target]
    if only["only_in_a"] or only["only_in_b"]:
        lines += ["", f"Not compared: only in A {only['only_in_a']}, only in B {only['only_in_b']}"]
    md = "\n".join(lines) + "\n"
    print(md)
    if args.md:
        Path(args.md).write_text(md)
    if args.json:
        Path(args.json).write_text(json.dumps({"a": ma, "b": mb, "per_target": per_target, **only}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
