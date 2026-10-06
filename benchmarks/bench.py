"""Reproducible benchmark harness — score our discovery against an answer key.

Metrics adapted from bug-hunter (MIT, © codexstar69), reframed for a system whose "finding" is a
RUNTIME-CONFIRMED exploit, not an LLM claim. That changes what the numbers mean, honestly:
  * precision is ~1 by construction — a confirmed finding has a replayed exploit behind it, so there are
    no false positives to weigh. We still report it.
  * recall over the IN-SCOPE labels (the bugs a dynamic probe can reach) is the real discovery score.
  * stability (run-to-run Jaccard) matters for an autonomous run — a flaky finder is useless to a jury.
  * cost = wall-time and HTTP requests per confirmed bug (discovery uses no model, so $ ≈ 0).

Out-of-scope labels (static-only like a weak JWT key, or RoE-excluded live-DoS) are reported separately,
never counted against recall — that would punish us for honouring the Rules of Engagement.

    python -m benchmarks.bench --target vampi --runs 3 [--out reports/bench_vampi.json]
"""
import argparse
import json
import statistics
import sys
import time
import urllib.request
from pathlib import Path

_SEV_WEIGHT = {"low": 1, "medium": 2, "high": 4, "critical": 8}


def _match(finding, label) -> bool:
    """A confirmed finding matches a label when the class agrees and the route lines up (tolerant:
    the label's route pattern appears in the finding's route, or vice versa)."""
    if finding.klass != label["klass"]:
        return False
    froute = finding.evidence.get("route", "").split(" ", 1)[-1]
    lroute = label["route"]
    return lroute in froute or froute in lroute or lroute == "*"


def _score_run(findings, labels) -> dict:
    in_scope = [l for l in labels if l["discovery"] == "dynamic"]
    matched_ids, matched_findings = set(), 0
    for l in in_scope:
        if any(_match(f, l) for f in findings):
            matched_ids.add(l["id"])
    for f in findings:
        if any(_match(f, l) for l in labels):
            matched_findings += 1
    recall = len(matched_ids) / len(in_scope) if in_scope else 0.0
    precision = matched_findings / len(findings) if findings else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    w_have = sum(_SEV_WEIGHT.get(l["severity"], 1) for l in in_scope if l["id"] in matched_ids)
    w_all = sum(_SEV_WEIGHT.get(l["severity"], 1) for l in in_scope)
    return {"found": len(findings), "matched_ids": sorted(matched_ids),
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "severity_weighted_recall": round(w_have / w_all, 3) if w_all else 0.0}


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a | b) else 1.0


def _vampi_discover():
    from benchmarks.crosslang_vampi import VAMPI_AUTH
    from src.pyauto.probes import ProbeCtx, probe, routes_from_openapi
    base = "http://127.0.0.1:5001"

    def seed():
        for _ in range(4):
            try:
                urllib.request.urlopen(base + "/createdb", timeout=10).read()
                return
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        raise RuntimeError("seed failed")
    seed()
    routes = routes_from_openapi("benchmark_workspace/VAmPI/openapi_specs/openapi3.yml")
    return probe(routes, ProbeCtx(base, VAMPI_AUTH, reseed=seed))


_TARGETS = {"vampi": (_vampi_discover, "benchmarks/labels/vampi.json")}


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmarks.bench")
    ap.add_argument("--target", default="vampi", choices=list(_TARGETS))
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    discover, labels_path = _TARGETS[args.target]
    labels = json.loads(Path(labels_path).read_text())["labels"]

    runs, durations, matched_sets = [], [], []
    for i in range(args.runs):
        t0 = time.monotonic()
        findings = discover()
        durations.append(time.monotonic() - t0)
        score = _score_run(findings, labels)
        runs.append(score)
        matched_sets.append(set(score["matched_ids"]))
        print(f"run {i + 1}: found {score['found']}, recall {score['recall']}, precision {score['precision']}, "
              f"F1 {score['f1']}, sev-weighted-recall {score['severity_weighted_recall']}, {durations[-1]:.1f}s")

    stability = statistics.mean(_jaccard(matched_sets[0], s) for s in matched_sets[1:]) if len(matched_sets) > 1 else 1.0
    in_scope = sum(1 for l in labels if l["discovery"] == "dynamic")
    out_scope = {l["discovery"]: 0 for l in labels if l["discovery"] != "dynamic"}
    for l in labels:
        if l["discovery"] != "dynamic":
            out_scope[l["discovery"]] += 1
    report = {
        "target": args.target, "runs": args.runs,
        "in_scope_labels": in_scope, "out_of_scope": out_scope,
        "recall": runs[0]["recall"], "precision": runs[0]["precision"], "f1": runs[0]["f1"],
        "severity_weighted_recall": runs[0]["severity_weighted_recall"],
        "stability_jaccard": round(stability, 3),
        "median_seconds": round(statistics.median(durations), 1),
        "bugs_per_run": round(statistics.mean(r["found"] for r in runs), 1),
        "seconds_per_bug": round(statistics.median(durations) / max(1, runs[0]["found"]), 1),
        "model_cost_usd": 0.0,  # discovery is deterministic + model-free
    }
    print("\n== benchmark ==")
    for k, v in report.items():
        print(f"  {k}: {v}")
    print(f"\nrecall {report['recall']} over {in_scope} in-scope bugs; "
          f"{out_scope} out of scope (static / RoE-excluded, scored separately); "
          f"stability {report['stability_jaccard']} across {args.runs} runs")
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
