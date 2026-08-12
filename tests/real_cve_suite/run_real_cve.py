#!/usr/bin/env python3
"""
Real-CVE suite — standalone runner.

Evaluates published CVEs in unmodified upstream source, independently of
`benchmark.py`. Everything the suite needs lives in this folder:

    setup.sh        materialises the vulnerable trees (git worktrees)
    drivers/        one C driver per CVE
    manifest.py     target definitions + verification contracts
    run_real_cve.py this runner

Usage:

    sh tests/real_cve_suite/setup.sh          # once, or after deleting the trees
    python -m tests.real_cve_suite.run_real_cve

The same targets are also reachable through the main harness:

    python benchmark.py --suite real_cve --harden

Every target is pre-flighted first: the tree is compiled UNPATCHED and its PoV
executed against it. A PoV that does not reproduce is disabled rather than
counted, so a patch can never be credited for fixing something never shown
broken.
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table

from src.main import setup_logging
from src.agent_orchestrator.orchestrator import Orchestrator, VulnerabilityReport
from src.agent_orchestrator.llm_client import LLMClient
from src.context_engine.tree_sitter_extractor import ContextExtractor
from src.patch_validator.hardening import PatchHardening, HardeningVerdict
from tests.standalone_support import preflight, harden_result, hardening_label
from tests.real_cve_suite.manifest import REAL_CVE, missing_trees

console = Console()


def run() -> int:
    setup_logging(verbose=False)
    console.print("\n[bold cyan]Real-CVE suite — published CVEs, unmodified upstream source[/]\n")

    absent = missing_trees()
    if absent:
        console.print(f"[yellow]{len(absent)} target(s) have no source tree: {', '.join(absent)}[/]")
        console.print("[yellow]Run: sh tests/real_cve_suite/setup.sh[/]\n")

    if not REAL_CVE:
        console.print("[red]No targets available. Nothing evaluated.[/]")
        return 1

    llm = LLMClient()
    extractor = ContextExtractor()
    hardener = PatchHardening()
    orchestrator = Orchestrator(llm, extractor, None, parallel=True)

    results = []
    start = time.time()

    for i, target in enumerate(REAL_CVE, 1):
        console.print(f"[bold]{i}/{len(REAL_CVE)}[/] {target.id}")

        pf = preflight(target)
        console.print(f"  [dim]pre-flight: {pf.summary()}[/]")
        if not pf.builds:
            console.print("  [red]SKIPPED — the unpatched tree does not build[/]")
            results.append({"target": target, "result": None,
                            "hardening": "NOT HARDENED", "preflight": pf})
            continue

        vuln = VulnerabilityReport(
            id=target.id, source=target.source, file_path=target.file_path,
            line_number=target.line_number, description=target.description,
            cwe_id=target.cwe_id, severity="critical",
        )
        res = orchestrator.process_vulnerability(
            vuln,
            build_command=target.build_command,
            pov_command=target.pov_command if pf.pov_usable else None,
            test_command=target.regression_command,
            source_dir=target.source_dir,
        )

        verdict = HardeningVerdict()
        if res.status == "patched":
            verdict = harden_result(target, res, hardener, extractor)
            label = hardening_label(verdict)
            if label.startswith("FALSIFIED"):
                res.status = "unresolved_hardening"
            console.print(f"  hardening: {label} [dim]{verdict.summary()[:110]}[/]")
        else:
            label = hardening_label(verdict)

        console.print(f"  {res.summary()}\n")
        results.append({"target": target, "result": res,
                        "hardening": label, "preflight": pf})

    _report(results, time.time() - start, llm)
    return 0


def _report(results, elapsed, llm):
    table = Table(title="Real-CVE suite")
    for col in ("CVE", "CWE", "Status", "Agent", "Hardening", "Time"):
        table.add_column(col)

    passed = pov_proven = 0
    for r in results:
        t, res, pf = r["target"], r["result"], r["preflight"]
        if res is None:
            table.add_row(t.id, t.cwe_id, "SKIPPED", "—", r["hardening"], "—")
            continue
        if res.status == "patched":
            passed += 1
            if pf.pov_usable:
                pov_proven += 1
        table.add_row(t.id, t.cwe_id, res.status.upper(),
                      res.winning_agent or "none", r["hardening"],
                      f"{res.elapsed_seconds:.1f}s")
    console.print(table)

    gated = sum(1 for r in results if r["preflight"].pov_usable)
    survived = sum(1 for r in results if r["hardening"] == "SURVIVED")
    console.print(
        f"\n[bold]Passed all gates: {passed}/{len(results)}[/] | "
        f"PoV-proven: {pov_proven}/{gated} | Survived hardening: {survived}/{passed} | "
        f"{elapsed:.1f}s | ${llm.get_usage_summary()['estimated_cost_usd']:.4f}\n"
    )

    out = PROJECT_ROOT / "reports" / "real_cve_report.md"
    out.parent.mkdir(exist_ok=True)
    lines = [
        "# Real-CVE Suite Report",
        "",
        "Published CVEs in **unmodified upstream source**. Each tree is checked out",
        "at the commit immediately before the security fix landed.",
        "",
        f"**Passed all gates:** {passed}/{len(results)} · "
        f"**PoV-proven:** {pov_proven}/{gated} · "
        f"**Survived hardening:** {survived}/{passed}",
        "",
        "| CVE | CWE | Status | Agent | Hardening | Pre-flight |",
        "| :-- | :-- | :----- | :---- | :-------- | :--------- |",
    ]
    for r in results:
        t, res, pf = r["target"], r["result"], r["preflight"]
        status = res.status.upper() if res else "SKIPPED"
        agent = (res.winning_agent or "none") if res else "—"
        lines.append(f"| {t.id} | {t.cwe_id} | **{status}** | {agent} | "
                     f"{r['hardening']} | {pf.summary()} |")
    out.write_text("\n".join(lines) + "\n")
    console.print(f"[dim]report: {out}[/]")


if __name__ == "__main__":
    raise SystemExit(run())
