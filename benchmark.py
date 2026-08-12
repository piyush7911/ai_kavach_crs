#!/usr/bin/env python3
"""
AI Kavach — Master Benchmark Harness

Design rule: every number this harness reports is measured during the run.
There are no placeholder constants. If something cannot be measured on this
platform it is reported as "not measured" together with the reason, never as
an assumed value.

Two things make the scoring honest:

  1. PRE-FLIGHT. Before any agent runs, every target is compiled UNPATCHED and
     its PoV command is executed. A PoV that does not reproduce on the original
     binary is disabled for the run and reported as such, so a patch can never
     be credited for "fixing" something that was never demonstrated broken.

  2. GATE ACCOUNTING. A patch is only counted as PoV-verified if the PoV gate
     actually executed and passed. Targets with no PoV are tracked separately.

Usage:
    python benchmark.py --suite [synthetic|juliet|real_world|all]
                        [--sequential] [--limit N] [--fuzz]
"""

import argparse
import csv
import json
import platform
import resource
import shutil
import math
import statistics
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from src.main import setup_logging
from src.agent_orchestrator.orchestrator import Orchestrator, VulnerabilityReport, PipelineResult
from src.agent_orchestrator.llm_client import LLMClient
from src.context_engine.tree_sitter_extractor import ContextExtractor
from src.patch_validator.drv_loop import DRVLoop, GATE_PASS, GATE_SKIPPED
from src.reporting.audit_report import AuditReportGenerator
from src.patch_validator.hardening import PatchHardening, HardeningVerdict
from src.patch_validator.formal import FormalVerifier, VerificationResult
from src.memory import MemorySystem
from tests.benchmarks.targets import Target, get_suite

console = Console()


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """
    Wilson score confidence interval for a binomial proportion.

    Reporting a bare "100%" from a single run of 37 targets overstates what the
    sample supports. The normal approximation is useless at p=1 (it gives a
    zero-width interval); the Wilson interval stays sensible at the boundary,
    which is exactly where our results sit.

    37/37 successes yields roughly [90.6%, 100%] at 95% confidence — still a
    strong claim, and one that survives scrutiny.
    """
    if trials == 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1 + z ** 2 / trials
    centre = (p + z ** 2 / (2 * trials)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / trials + z ** 2 / (4 * trials ** 2))
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def format_rate(successes: int, trials: int) -> str:
    """Rate with its 95% Wilson interval, e.g. '100% [90.6, 100]'."""
    if trials == 0:
        return "n/a"
    lo, hi = wilson_interval(successes, trials)
    return f"{successes / trials * 100:.1f}% [{lo * 100:.1f}, {hi * 100:.1f}]"


class PreflightResult:
    """Whether a target's PoV genuinely reproduces on the unpatched original."""

    def __init__(self, target: Target):
        self.target = target
        self.build_ok = False
        self.build_error = ""
        self.pov_reproduces = False
        self.pov_detail = ""
        self.regression_baseline_ok = False
        self.regression_detail = ""

    @property
    def pov_usable(self) -> bool:
        return self.build_ok and self.pov_reproduces

    @property
    def regression_usable(self) -> bool:
        """
        Whether the regression test already passes on the UNPATCHED original.

        This is recorded for transparency but does NOT disable the gate: for a
        target whose only input path is the vulnerable one (e.g. the off-by-one
        loop, which trips the sanitizer on every input), the baseline
        legitimately fails while the post-patch check is still meaningful.
        """
        return self.build_ok and self.regression_baseline_ok


def preflight(target: Target) -> PreflightResult:
    """
    Compile the target UNPATCHED and confirm the PoV fails on it.

    This is what licenses us to use the PoV as a pass/fail gate later: we have
    observed it detecting the real bug.
    """
    res = PreflightResult(target)

    with tempfile.TemporaryDirectory(prefix="kavach_pre_") as tmp:
        workspace = Path(tmp)
        try:
            src = DRVLoop._materialise(workspace, target.file_path, target.source_dir)
        except FileNotFoundError as e:
            res.build_error = str(e)
            return res

        binary = workspace / "kavach_target"
        ctx = {
            "src": str(src), "srcdir": str(src.parent),
            "bin": str(binary), "workspace": str(workspace),
        }

        ok, detail = DRVLoop._run(DRVLoop.expand(target.build_command, ctx), "Build", cwd=workspace)
        res.build_ok = ok
        if not ok:
            res.build_error = detail
            return res

        if target.pov_command:
            # PoV scripts exit non-zero when the vulnerability IS present.
            ok, detail = DRVLoop._run(DRVLoop.expand(target.pov_command, ctx), "PoV", cwd=workspace)
            res.pov_reproduces = not ok
            res.pov_detail = detail if not ok else "PoV did NOT reproduce on the original binary"

        if target.regression_command:
            # A regression test must pass on the ORIGINAL, otherwise it is
            # measuring a pre-existing failure rather than damage from a patch.
            ok, detail = DRVLoop._run(
                DRVLoop.expand(target.regression_command, ctx), "Regression", cwd=workspace
            )
            res.regression_baseline_ok = ok
            res.regression_detail = "" if ok else detail

    return res


class BenchmarkHarness:
    def __init__(self, output_dir="reports/benchmark_runs", parallel=True, harden=False,
                 memory=False, formal=False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = parallel
        self.harden = harden
        self.hardener = PatchHardening() if harden else None
        self.hardening_verdicts: dict[str, HardeningVerdict] = {}
        self.formal_results: dict[str, VerificationResult] = {}
        self.formal = FormalVerifier() if formal else None
        self.memory = MemorySystem() if memory else None
        self.llm_client = LLMClient()
        self.extractor = ContextExtractor()
        self.suites: list[dict] = []
        self.records: list[dict] = []
        self.all_results: list[tuple[Target, PipelineResult]] = []
        self.preflight_records: list[dict] = []

    # -- execution ----------------------------------------------------------

    def run_suite(self, name: str, targets: list[Target]):
        if not targets:
            console.print(f"[yellow]Skipping {name}: no targets[/]")
            return

        label = name
        console.print(f"\n[bold cyan]=== {label} — {len(targets)} targets ===[/]")

        console.print("[dim]Pre-flight: verifying each PoV reproduces on the unpatched original...[/]")
        preflights = {}
        for t in targets:
            pf = preflight(t)
            preflights[t.id] = pf
            self.preflight_records.append({
                "Suite": label, "ID": t.id,
                "Original_Builds": pf.build_ok,
                "PoV_Configured": t.pov_command is not None,
                "PoV_Reproduces_On_Original": pf.pov_reproduces,
                "PoV_NA_Reason": t.pov_na_reason,
                "Regression_Configured": t.regression_command is not None,
                "Regression_Passes_On_Original": pf.regression_baseline_ok,
                "Build_Error": pf.build_error[:300],
            })
            if not pf.build_ok:
                console.print(f"  [red]✗ {t.id}: original does not build — target excluded[/]")
            elif t.pov_command and not pf.pov_reproduces:
                console.print(f"  [yellow]! {t.id}: PoV did not reproduce — PoV gate disabled[/]")

        usable = [t for t in targets if preflights[t.id].build_ok]
        excluded = len(targets) - len(usable)
        if excluded:
            console.print(f"  [red]{excluded} target(s) excluded: unpatched original fails to build[/]")

        orchestrator = Orchestrator(
            self.llm_client,
            self.extractor,
            None,
            parallel=self.parallel,
            memory=self.memory,
        )

        suite_start = time.time()
        results = []
        for i, t in enumerate(usable, 1):
            console.print(f"  [{i}/{len(usable)}] {t.id} …")
            pf = preflights[t.id]
            vuln = VulnerabilityReport(
                id=t.id, source=t.source, file_path=t.file_path,
                line_number=t.line_number, description=t.description,
                cwe_id=t.cwe_id, severity=t.severity,
            )
            result = orchestrator.process_vulnerability(
                vuln,
                build_command=t.build_command,
                # Only gate on a PoV we proved detects the real bug.
                pov_command=t.pov_command if pf.pov_usable else None,
                test_command=t.regression_command,
                source_dir=t.source_dir,
            )
            results.append(result)
            self.all_results.append((t, result))

            if self.hardener and result.status == "patched":
                verdict = self._harden_patch(t, result)
                self.hardening_verdicts[t.id] = verdict
                if not verdict.survived:
                    # The patch cleared every gate but hardening falsified it.
                    # Downgrade it rather than report a fix we can't defend.
                    result.status = "unresolved_hardening"
                    console.print(f"      [red]HARDENING FAILED: {verdict.summary()}[/]")
                else:
                    console.print(f"      [dim]hardening: {verdict.summary()}[/]")
                    if self.memory and verdict.overfitting_checked:
                        # Only a patch that survived falsification earns the
                        # higher-confidence 'hardened' status in memory.
                        for pattern in self.memory.semantic.patterns:
                            if pattern.source_target == t.id:
                                pattern.hardened = True
                        self.memory.semantic.save()

            if self.formal and result.status == "patched":
                fr = self._verify_formally(t, result)
                self.formal_results[t.id] = fr
                if fr.status != "unavailable":
                    colour = {"proven": "green", "violated": "red"}.get(fr.status, "yellow")
                    console.print(f"      [{colour}]{fr.summary()}[/]")
                    if fr.status == "violated":
                        # A counterexample is a stronger signal than any test:
                        # it exhibits an input on which the patch is still unsafe.
                        result.status = "unresolved_formal"

            self._record(label, t, result, pf)
            console.print(f"      {result.summary()}")

        duration = time.time() - suite_start
        self._summarise_suite(label, name, usable, excluded, results, duration)

    def _harden_patch(self, t: Target, result: PipelineResult) -> HardeningVerdict:
        """
        Re-apply the winning patch to a clean copy and try to falsify it.

        The DRV workspaces are temporary, so the patch is re-applied here rather
        than reused. Hardening runs on the same bytes the gates approved.
        """
        import tempfile as _tf
        verdict = HardeningVerdict()
        report = result.agent_reports.get(result.winning_agent)
        winning = report.winning_iteration if report else None
        if not winning:
            verdict.skipped_reason = "no winning iteration recorded"
            return verdict

        with _tf.TemporaryDirectory(prefix="kavach_harden_") as tmp:
            work = Path(tmp)
            try:
                patched = DRVLoop._materialise(work, t.file_path, t.source_dir)
            except FileNotFoundError as e:
                verdict.skipped_reason = str(e)
                return verdict

            applied = False
            if winning.replacement:
                name, source = winning.replacement
                applied = self.extractor.replace_function(str(patched), name, source)
            if not applied and winning.patch_diff:
                applied, _ = DRVLoop._apply_patch(work, patched, winning.patch_diff)
            if not applied:
                verdict.skipped_reason = "could not re-apply the winning patch"
                return verdict

            return self.hardener.harden(
                target_id=t.id,
                original_source=Path(t.file_path),
                patched_source=patched,
                build_command=t.build_command,
                behaviour_contract=t.behaviour_contract,
                evasion_command=t.evasion_command,
            )

    def _verify_formally(self, t: Target, result: PipelineResult) -> VerificationResult:
        """
        Re-apply the winning patch and prove it with CBMC over all inputs.

        Only targets with a proof harness are attempted; everything else is
        reported `unavailable`, never as a pass.
        """
        import tempfile as _tf
        harness = Path("tests/benchmarks/cbmc_harnesses") / f"{t.id}.c"
        if not harness.exists():
            r = VerificationResult()
            r.detail = "no proof harness for this target"
            return r

        report = result.agent_reports.get(result.winning_agent) if result.winning_agent else None
        winning = report.winning_iteration if report else None
        if not winning:
            r = VerificationResult(); r.detail = "no winning iteration"; return r

        with _tf.TemporaryDirectory(prefix="kavach_formal_") as tmp:
            work = Path(tmp)
            try:
                patched = DRVLoop._materialise(work, t.file_path, t.source_dir)
            except FileNotFoundError as e:
                r = VerificationResult(); r.detail = str(e); return r

            applied = False
            if winning.replacement:
                name, source = winning.replacement
                applied = self.extractor.replace_function(str(patched), name, source)
            if not applied and winning.patch_diff:
                applied, _ = DRVLoop._apply_patch(work, patched, winning.patch_diff)
            if not applied:
                r = VerificationResult()
                r.detail = "could not re-apply the winning patch"
                return r

            return self.formal.verify_patched(
                patched, harness, work, unwind=t.cbmc_unwind
            )

    def _record(self, suite: str, t: Target, r: PipelineResult, pf: PreflightResult):
        """One row per target with fully measured per-target facts."""
        winning = None
        if r.winning_agent and r.agent_reports.get(r.winning_agent):
            winning = r.agent_reports[r.winning_agent].winning_iteration

        iterations = [
            rep.total_iterations for rep in r.agent_reports.values() if rep is not None
        ]
        stages = Counter(
            rep.last_failure_stage for rep in r.agent_reports.values()
            if rep is not None and not rep.success and rep.last_failure_stage
        )

        self.records.append({
            "Suite": suite,
            "ID": t.id,
            "CWE": t.cwe_id,
            "Complexity": t.complexity,
            "File": t.file_path,
            "Status": r.status,
            "Winning_Agent": r.winning_agent or "",
            "Context_Method": r.context_method,
            "PoV_Available": pf.pov_usable,
            "PoV_Gate": winning.pov_ok if winning else GATE_SKIPPED,
            "Build_Gate": winning.syntax_ok if winning else GATE_SKIPPED,
            "Regression_Gate": winning.regression_ok if winning else GATE_SKIPPED,
            "Patch_Lines": winning.patch_line_count if winning else "",
            "Max_Agent_Iterations": max(iterations) if iterations else 0,
            "Failure_Stages": ";".join(f"{k}:{v}" for k, v in stages.items()),
            "Seconds": round(r.elapsed_seconds, 2),
            "Cost_USD": round(r.total_cost_usd, 6),
            "Formal": self.formal_results[t.id].status if t.id in self.formal_results else "",
            "Formal_Unwind": self.formal_results[t.id].unwind if t.id in self.formal_results else "",
            "Hardening": self.hardening_verdicts[t.id].summary() if t.id in self.hardening_verdicts else "",
            "Hardening_Survived": self.hardening_verdicts[t.id].survived if t.id in self.hardening_verdicts else "",
        })

    def _summarise_suite(self, label, name, targets, excluded, results, duration):
        rows = [rec for rec in self.records if rec["Suite"] == label]
        patched = [rec for rec in rows if rec["Status"] == "patched"]
        pov_gated = [rec for rec in rows if rec["PoV_Available"]]
        pov_proven = [rec for rec in patched if rec["PoV_Gate"] == GATE_PASS]
        regress_proven = [rec for rec in patched if rec["Regression_Gate"] == GATE_PASS]
        patch_sizes = [rec["Patch_Lines"] for rec in patched if rec["Patch_Lines"] != ""]

        self.suites.append({
            "Suite": name,
            "Label": label,
            "Targets_Attempted": len(targets),
            "Targets_Excluded_Build_Failure": excluded,
            "Patched_All_Gates": len(patched),
            "Success_Rate": f"{len(patched) / len(targets) * 100:.1f}%" if targets else "n/a",
            "Success_Rate_95CI": format_rate(len(patched), len(targets)),
            "Targets_With_Reproducible_PoV": len(pov_gated),
            "PoV_Verified_Fixes": len(pov_proven),
            "PoV_Verified_Rate": (
                f"{len(pov_proven) / len(pov_gated) * 100:.1f}%" if pov_gated else "n/a"
            ),
            "Regression_Verified_Fixes": len(regress_proven),
            "Mean_Patch_Lines": round(statistics.mean(patch_sizes), 1) if patch_sizes else None,
            "Median_Patch_Lines": statistics.median(patch_sizes) if patch_sizes else None,
            "Duration_s": round(duration, 2),
        })

        console.print(
            f"[bold]{label}[/]: {len(patched)}/{len(targets)} passed all configured gates; "
            f"{len(pov_proven)}/{len(pov_gated)} proven by PoV replay; {duration:.1f}s"
        )

    def run_fuzz_discovery(self, targets: list[Target], engine: str, seconds: int):
        """
        End-to-end discovery suite: fuzz → triage → patch → verify.

        Unlike the other suites, the vulnerability location is not declared in
        advance — it comes from the stack trace of a crash the fuzzer found. The
        PoV gate replays that same discovered input against the patched build.
        """
        from src.fuzz_pipeline import FuzzDiscoveryPipeline

        harnessed = set(FuzzDiscoveryPipeline.harnessed_targets())
        eligible = [t for t in targets if t.id in harnessed]
        if not eligible:
            console.print("[yellow]No targets have fuzz harnesses; skipping discovery suite[/]")
            return

        label = f"Fuzz Discovery ({engine})"
        console.print(f"\n[bold cyan]=== {label} — {len(eligible)} harnessed targets ===[/]")

        orchestrator = Orchestrator(self.llm_client, self.extractor, None, parallel=self.parallel)
        pipeline = FuzzDiscoveryPipeline(orchestrator, engine=engine)

        start = time.time()
        crashes_total = bugs_total = patched_total = 0

        for i, t in enumerate(eligible, 1):
            console.print(f"  [{i}/{len(eligible)}] fuzzing {t.id} for {seconds}s …")
            discovery = pipeline.run(
                t.id, t.file_path, t.build_command, t.regression_command, seconds=seconds
            )
            crashes_total += discovery.crashes_found
            bugs_total += discovery.unique_bugs
            patched_total += discovery.patched

            console.print(
                f"      {discovery.crashes_found} crash input(s) → "
                f"{discovery.unique_bugs} distinct bug(s) → {discovery.patched} verified fix(es)"
                + (f" [red]{discovery.error}[/]" if discovery.error else "")
            )

            for cluster, pr in zip(discovery.clusters, discovery.patch_results):
                sig = cluster.signature
                self.all_results.append((t, pr))
                winning = None
                if pr.winning_agent and pr.agent_reports.get(pr.winning_agent):
                    winning = pr.agent_reports[pr.winning_agent].winning_iteration
                self.records.append({
                    "Suite": label, "ID": pr.vulnerability.id, "CWE": pr.vulnerability.cwe_id,
                    "Complexity": t.complexity, "File": sig.file_path,
                    "Status": pr.status, "Winning_Agent": pr.winning_agent or "",
                    "Context_Method": pr.context_method,
                    "PoV_Available": True,           # the fuzzer's own crashing input
                    "PoV_Gate": winning.pov_ok if winning else GATE_SKIPPED,
                    "Build_Gate": winning.syntax_ok if winning else GATE_SKIPPED,
                    "Regression_Gate": winning.regression_ok if winning else GATE_SKIPPED,
                    "Patch_Lines": winning.patch_line_count if winning else "",
                    "Max_Agent_Iterations": max(
                        (r.total_iterations for r in pr.agent_reports.values() if r), default=0
                    ),
                    "Failure_Stages": ";".join(
                        f"{r.last_failure_stage}:1" for r in pr.agent_reports.values()
                        if r and not r.success and r.last_failure_stage
                    ),
                    "Seconds": round(pr.elapsed_seconds, 2),
                    "Cost_USD": round(pr.total_cost_usd, 6),
                    "Discovered_Crash_Class": sig.crash_class,
                    "Discovered_Location": f"{Path(sig.file_path).name}:{sig.line_number}",
                })

        duration = round(time.time() - start, 2)
        self.suites.append({
            "Suite": "Fuzz Discovery", "Label": label,
            "Targets_Attempted": len(eligible),
            "Targets_Excluded_Build_Failure": 0,
            "Patched_All_Gates": patched_total,
            "Success_Rate": f"{patched_total / bugs_total * 100:.1f}%" if bugs_total else "n/a",
            "Targets_With_Reproducible_PoV": bugs_total,
            "PoV_Verified_Fixes": patched_total,
            "PoV_Verified_Rate": f"{patched_total / bugs_total * 100:.1f}%" if bugs_total else "n/a",
            "Regression_Verified_Fixes": patched_total,
            "Mean_Patch_Lines": None, "Median_Patch_Lines": None,
            "Duration_s": duration,
            "Crash_Inputs_Found": crashes_total,
            "Distinct_Bugs_After_Triage": bugs_total,
        })
        console.print(
            f"[bold]{label}[/]: {crashes_total} crash input(s) → {bugs_total} distinct bug(s) "
            f"→ {patched_total} verified fix(es) in {duration}s"
        )

    # -- reporting ----------------------------------------------------------

    def generate_reports(self):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        run_dir = self.output_dir / timestamp
        run_dir.mkdir(parents=True)

        table = Table(title="AI Kavach Benchmark — measured results")
        for col, just in [("Suite", "left"), ("Targets", "right"), ("All Gates", "right"),
                          ("Rate", "right"), ("PoV-Proven", "right"), ("Time (s)", "right")]:
            table.add_column(col, justify=just)
        for s in self.suites:
            table.add_row(
                s["Label"], str(s["Targets_Attempted"]), str(s["Patched_All_Gates"]),
                s["Success_Rate"],
                f"{s['PoV_Verified_Fixes']}/{s['Targets_With_Reproducible_PoV']}",
                str(s["Duration_s"]),
            )
        console.print(table)

        self._write_csv(run_dir / "per_target_results.csv", self.records)
        self._write_csv(run_dir / "suite_summary.csv", self.suites)
        self._write_csv(run_dir / "preflight_pov_validation.csv", self.preflight_records)

        summary = self._build_summary(timestamp)
        (run_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=4, default=str))
        (run_dir / "benchmark_summary.md").write_text(self._build_markdown(summary))

        audit = AuditReportGenerator(output_dir=str(run_dir))
        gate_notes = {
            t.id: {"pov": t.pov_na_reason, "regression": t.regression_na_reason}
            for t, _ in self.all_results
        }
        audit.generate_report(
            [r for _, r in self.all_results], report_name="audit", gate_notes=gate_notes
        )

        console.print(f"📊 Run artifacts: [bold]{run_dir}[/]")
        return run_dir

    @staticmethod
    def _write_csv(path: Path, rows: list[dict]):
        if not rows:
            return
        fields = list({k: None for row in rows for k in row})
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def _build_summary(self, timestamp: str) -> dict:
        usage = self.llm_client.get_usage_summary()
        attempted = sum(s["Targets_Attempted"] for s in self.suites)
        patched = sum(s["Patched_All_Gates"] for s in self.suites)
        pov_gated = sum(s["Targets_With_Reproducible_PoV"] for s in self.suites)
        pov_proven = sum(s["PoV_Verified_Fixes"] for s in self.suites)

        patch_sizes = [r["Patch_Lines"] for r in self.records
                       if r["Status"] == "patched" and r["Patch_Lines"] != ""]
        iterations = [r["Max_Agent_Iterations"] for r in self.records if r["Max_Agent_Iterations"]]

        stage_counter = Counter()
        for r in self.records:
            for item in filter(None, r["Failure_Stages"].split(";")):
                stage, count = item.split(":")
                stage_counter[stage] += int(count)

        # Peak RSS of this process tree, as reported by the OS.
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_mb = round(rss / (1024 * 1024 if sys.platform == "darwin" else 1024), 1)

        return {
            "timestamp": timestamp,
            "platform": f"{platform.system()} {platform.machine()} / Python {platform.python_version()}",
            "mode": "parallel ensemble" if self.parallel else "sequential ensemble",
            "models": self.llm_client.models,
            "totals": {
                "targets_attempted": attempted,
                "patched_all_configured_gates": patched,
                "success_rate": f"{patched / attempted * 100:.1f}%" if attempted else "n/a",
                "success_rate_95ci_wilson": format_rate(patched, attempted),
                "targets_with_reproducible_pov": pov_gated,
                "pov_verified_fixes": pov_proven,
                "pov_verified_rate": f"{pov_proven / pov_gated * 100:.1f}%" if pov_gated else "n/a",
                "pov_verified_rate_95ci_wilson": format_rate(pov_proven, pov_gated),
            },
            "suites": self.suites,
            "patch_quality": {
                "measured_over_patches": len(patch_sizes),
                "mean_changed_lines": round(statistics.mean(patch_sizes), 1) if patch_sizes else None,
                "median_changed_lines": statistics.median(patch_sizes) if patch_sizes else None,
                "max_changed_lines": max(patch_sizes) if patch_sizes else None,
                "under_15_lines_pct": (
                    round(sum(1 for p in patch_sizes if p < 15) / len(patch_sizes) * 100, 1)
                    if patch_sizes else None
                ),
            },
            "drv_loop": {
                "mean_iterations_to_resolution": round(statistics.mean(iterations), 2) if iterations else None,
                "max_iterations_observed": max(iterations) if iterations else None,
                "rejection_stages": dict(stage_counter),
            },
            "llm_usage": {
                "api_calls": usage["total_calls"],
                "input_tokens": usage["total_input_tokens"],
                "output_tokens": usage["total_output_tokens"],
                "estimated_cost_usd": usage["estimated_cost_usd"],
                "unpriced_tokens": usage["unpriced_tokens"],
                "pricing_note": "Cost derived from per-model published rates in LLMClient.PRICING.",
            },
            "resource_usage": {
                "peak_rss_mb_orchestrator_process": rss_mb,
                "note": (
                    "Peak RSS of the harness process only (getrusage RUSAGE_SELF). "
                    "CPU utilisation is not measured; no value is reported for it."
                ),
            },
            "component_availability": self._component_availability(),
            "not_measured": [
                "Detection precision/recall — this run patches a curated target list; "
                "no labelled detection corpus was scanned, so no precision or recall "
                "figure can be derived.",
                "CPU utilisation — not sampled during the run.",
                "Fuzzing throughput / AFL++ coverage — the fuzzing and CASR modules "
                "are not exercised by this harness.",
            ],
        }

    @staticmethod
    def _component_availability() -> dict:
        """Probe each analysis component so the report states what was really usable."""
        from src.analysis_engine.fuzzer_manager import FuzzerManager
        from src.analysis_engine.crash_triage import CrashTriage
        from src.analysis_engine.driller_monitor import DrillerEngine

        fm = FuzzerManager("benchmark_workspace/fuzzing")
        engines = fm.available_engines()
        drill_ok, drill_why = DrillerEngine.self_test()
        # semgrep usually lives beside the running interpreter (conda env bin),
        # which is not necessarily on PATH.
        semgrep = bool(shutil.which("semgrep")) or (Path(sys.executable).parent / "semgrep").exists()

        return {
            "fuzzing_engines_available": engines or ["none"],
            "crash_triage_backend": "casr" if CrashTriage._casr_available() else "native-asan",
            "concolic_driller_usable": drill_ok,
            "concolic_driller_detail": drill_why,
            "semgrep_on_path": semgrep,
        }

    def _build_markdown(self, s: dict) -> str:
        md = [
            "# AI Kavach Benchmark Report",
            "",
            f"**Run:** {s['timestamp']}  ",
            f"**Platform:** {s['platform']}  ",
            f"**Mode:** {s['mode']}  ",
            f"**Models:** {json.dumps(s['models'])}",
            "",
            "Every figure below was measured during this run. Quantities that could "
            "not be measured are listed in *Not Measured* rather than estimated.",
            "",
            "## 1. Results by Suite",
            "",
            "| Suite | Targets | Passed All Gates | Rate | Reproducible PoV | PoV-Proven Fixes | Time (s) |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for x in s["suites"]:
            md.append(
                f"| {x['Label']} | {x['Targets_Attempted']} | {x['Patched_All_Gates']} | "
                f"{x['Success_Rate']} | {x['Targets_With_Reproducible_PoV']} | "
                f"{x['PoV_Verified_Fixes']} | {x['Duration_s']} |"
            )

        t = s["totals"]
        md += [
            "",
            "## 2. Totals",
            "",
            f"- Targets attempted: **{t['targets_attempted']}**",
            f"- Passed every configured gate: **{t['patched_all_configured_gates']}** "
            f"({t['success_rate']}, 95% CI {t['success_rate_95ci_wilson'].split(' ',1)[1]})",
            f"- Targets with a PoV that provably reproduces on the unpatched original: "
            f"**{t['targets_with_reproducible_pov']}**",
            f"- Fixes proven by PoV replay: **{t['pov_verified_fixes']}** ({t['pov_verified_rate']})",
            "",
            "> A patch counted under *Passed every configured gate* compiled under "
            "ASan+UBSan and survived every gate available for its target. Only the "
            "*PoV-proven* subset is dynamically demonstrated to remove the vulnerability.",
            "",
            "## 3. Patch Quality (measured)",
            "",
        ]
        q = s["patch_quality"]
        if q["measured_over_patches"]:
            md += [
                f"- Patches measured: {q['measured_over_patches']}",
                f"- Mean changed lines: {q['mean_changed_lines']}",
                f"- Median changed lines: {q['median_changed_lines']}",
                f"- Largest patch: {q['max_changed_lines']} lines",
                f"- Under 15 changed lines: {q['under_15_lines_pct']}%",
            ]
        else:
            md.append("- No validated patches to measure.")

        d = s["drv_loop"]
        md += [
            "",
            "## 4. DRV Loop Behaviour (measured)",
            "",
            f"- Mean agent iterations per target: {d['mean_iterations_to_resolution']}",
            f"- Maximum iterations observed: {d['max_iterations_observed']}",
            "- Rejection stages (why patches were sent back):",
        ]
        md += ([f"  - `{k}`: {v}" for k, v in sorted(d["rejection_stages"].items(), key=lambda kv: -kv[1])]
               or ["  - none recorded"])

        u = s["llm_usage"]
        md += [
            "",
            "## 5. LLM Usage (measured)",
            "",
            f"- API calls: {u['api_calls']}",
            f"- Input tokens: {u['input_tokens']:,}",
            f"- Output tokens: {u['output_tokens']:,}",
            f"- Estimated cost: ${u['estimated_cost_usd']:.4f}",
            f"- {u['pricing_note']}",
            "",
            "## 6. Resource Usage (measured)",
            "",
            f"- Peak RSS (harness process): {s['resource_usage']['peak_rss_mb_orchestrator_process']} MB",
            f"- {s['resource_usage']['note']}",
            "",
            "## 7. Component Availability (probed this run)",
            "",
        ]
        c = s["component_availability"]
        md += [
            f"- Fuzzing engines available: {', '.join(c['fuzzing_engines_available'])}",
            f"- Crash triage backend: {c['crash_triage_backend']}",
            f"- Semgrep on PATH: {c['semgrep_on_path']}",
            f"- Concolic (Driller/angr) usable: **{c['concolic_driller_usable']}** — {c['concolic_driller_detail']}",
            "",
            "## 8. Not Measured",
            "",
        ]
        md += [f"- {n}" for n in s["not_measured"]]
        md.append("")
        return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="AI Kavach CRS benchmark harness")
    parser.add_argument("--suite",
                        choices=["synthetic", "juliet", "real_world", "real_cve", "all", "fuzz"],
                        required=True,
                        help="'fuzz' runs ONLY the fuzz-discovery suite (implies --fuzz)")
    parser.add_argument("--sequential", action="store_true",
                        help="Run agents sequentially instead of the parallel ensemble")
    parser.add_argument("--limit", type=int, help="Only run the first N targets of each suite")
    parser.add_argument("--only", help=(
        "Comma-separated target IDs to run (e.g. SYN-06-OFF-BY-ONE,SYN-09-CMD-INJECTION). "
        "Use this to re-run just the targets that previously failed."))
    parser.add_argument("--memory", action="store_true",
                        help=("Enable cross-run agent memory: recall validated fix "
                              "patterns for similar bugs, and learn from this run. "
                              "Off by default so benchmark runs stay reproducible."))
    parser.add_argument("--formal", action="store_true",
                        help=("Prove the winning patch with CBMC over ALL inputs within a "
                              "per-target unwind bound. Requires a proof harness in "
                              "tests/benchmarks/cbmc_harnesses/; targets without one are "
                              "reported 'unavailable', never as proven."))
    parser.add_argument("--harden", action="store_true",
                        help=("After a patch passes every gate, try to FALSIFY it: "
                              "re-fuzz the patched build for an overfitted fix, and "
                              "differential-test it against the original for behaviour "
                              "changes. Patches that fail are downgraded."))
    parser.add_argument("--fuzz", action="store_true",
                        help="Also run the fuzz-discovery suite (fuzz → triage → patch → verify)")
    parser.add_argument("--fuzz-engine", choices=["libfuzzer", "afl++"], default="libfuzzer")
    parser.add_argument("--fuzz-seconds", type=int, default=30,
                        help="Fuzzing budget per target (default 30s)")
    args = parser.parse_args()

    setup_logging(verbose=False)
    harness = BenchmarkHarness(parallel=not args.sequential, harden=args.harden, memory=args.memory, formal=args.formal)

    if args.suite == "fuzz":
        suite_names = []
        args.fuzz = True
    else:
        suite_names = (["synthetic", "juliet", "real_world", "real_cve"]
                       if args.suite == "all" else [args.suite])
    pretty = {"synthetic": "Synthetic", "juliet": "NIST Juliet",
              "real_world": "Real World (cJSON)", "real_cve": "Real CVE (published)"}

    only = {t.strip() for t in args.only.split(",")} if args.only else None

    for key in suite_names:
        targets = get_suite(key)
        if only:
            targets = [t for t in targets if t.id in only]
        if args.limit:
            targets = targets[:args.limit]
        harness.run_suite(pretty[key], targets)

    if args.fuzz:
        targets = get_suite("synthetic")
        if only:
            targets = [t for t in targets if t.id in only]
        if args.limit:
            targets = targets[:args.limit]
        harness.run_fuzz_discovery(targets, args.fuzz_engine, args.fuzz_seconds)


    if harness.memory:
        console.print(f"[dim]memory: {harness.memory.stats()}[/]")

    harness.generate_reports()


if __name__ == "__main__":
    main()
