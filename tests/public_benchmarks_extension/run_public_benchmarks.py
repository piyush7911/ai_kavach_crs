#!/usr/bin/env python3
"""
Public Benchmarks Extension Suite Evaluation Harness.
Executes AI Kavach on NIST Juliet expansion, DARPA CGC MultiOS, and Historical CVEs.
Generates report: reports/public_benchmarks_report.md
"""

import sys
import time
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.main import setup_logging
from src.agent_orchestrator.orchestrator import Orchestrator, VulnerabilityReport
from src.agent_orchestrator.llm_client import LLMClient
from src.context_engine.tree_sitter_extractor import ContextExtractor
from src.patch_validator.hardening import PatchHardening, HardeningVerdict
from tests.standalone_support import preflight, harden_result, hardening_label
from tests.public_benchmarks_extension.manifest import PUBLIC_EXTENSION_TARGETS

console = Console()

def run_public_extension_suite():
    setup_logging(verbose=False)
    console.print("\n[bold cyan]🌐 Starting Public Benchmarks Extension Suite[/bold cyan]\n")
    
    llm_client = LLMClient()
    extractor = ContextExtractor()
    hardener = PatchHardening(
        harness_dir=str(Path(__file__).parent / "fuzz_harnesses")
    )
    
    orchestrator = Orchestrator(
        llm_client=llm_client,
        context_extractor=extractor,
        parallel=True
    )
    
    results = []
    start_time = time.time()
    
    for idx, target in enumerate(PUBLIC_EXTENSION_TARGETS, 1):
        console.print(f"[bold green][{idx}/{len(PUBLIC_EXTENSION_TARGETS)}] Target: {target.id}[/bold green]")
        console.print(f"  Suite: {target.suite} | CWE: {target.cwe_id}")
        console.print(f"  Description: {target.description}")
        
        # --- PRE-FLIGHT: is this target's contract even sound? ---
        pf = preflight(target)
        console.print(f"  [dim]pre-flight: {pf.summary()}[/dim]")
        if not pf.builds:
            console.print("  [red]SKIPPED — unpatched original does not build[/red]")
            results.append({"target": target, "result": None,
                            "hardening": "NOT HARDENED", "preflight": pf})
            console.print("-" * 60)
            continue

        vuln = VulnerabilityReport(
            id=target.id,
            source="manual",
            file_path=target.file_path,
            line_number=target.line_number,
            description=target.description,
            cwe_id=target.cwe_id,
            severity="critical"
        )

        res = orchestrator.process_vulnerability(
            vuln,
            build_command=target.build_command,
            # Gate only on a PoV proven to detect the real bug.
            pov_command=target.pov_command if pf.pov_usable else None,
            test_command=target.regression_command
        )

        # --- HARDENING: try to falsify a patch that cleared every gate ---
        h_verdict = HardeningVerdict()
        if res.status.lower() == "patched":
            console.print("  [yellow]Hardening (falsification)...[/yellow]")
            h_verdict = harden_result(target, res, hardener, extractor)
        status_label = hardening_label(h_verdict)
        if h_verdict.skipped_reason:
            console.print(f"  [yellow]Hardening: NOT HARDENED — {h_verdict.skipped_reason}[/yellow]")
        elif status_label.startswith("FALSIFIED"):
            console.print(f"  [red]Hardening: {status_label} — {h_verdict.summary()}[/red]")
            res.status = "unresolved_hardening"
        else:
            console.print(f"  [green]Hardening: {status_label}[/green] [dim]{h_verdict.summary()}[/dim]")

        results.append({"target": target, "result": res,
                        "hardening": status_label, "preflight": pf,
                        "hardening_detail": h_verdict.summary()})
        console.print("-" * 60)
        
    total_duration = time.time() - start_time
    
    table = Table(title="Public Benchmarks Extension Summary")
    table.add_column("Target ID", style="cyan")
    table.add_column("Suite", style="yellow")
    table.add_column("CWE", style="magenta")
    table.add_column("Status", style="bold green")
    table.add_column("Winning Agent", style="blue")
    table.add_column("Hardening", style="green")
    table.add_column("Time (s)", justify="right")
    
    passed = 0
    pov_proven = 0
    for r in results:
        t = r["target"]
        res = r["result"]
        if res is None:
            table.add_row(t.id, t.cwe_id, "SKIPPED", "—", r["hardening"], "—")
            continue
        if res.status.lower() == "patched":
            passed += 1
            if r["preflight"].pov_usable:
                pov_proven += 1
        table.add_row(
            t.id,
            t.suite,
            t.cwe_id,
            res.status.upper(),
            res.winning_agent or "None",
            r["hardening"],
            f"{res.elapsed_seconds:.2f}"
        )
        
    console.print(table)
    survived = sum(1 for r in results if r["hardening"] == "SURVIVED")
    pov_gated = sum(1 for r in results if r["preflight"].pov_usable)
    console.print(
        f"\n[bold]Passed all configured gates: {passed}/{len(PUBLIC_EXTENSION_TARGETS)}[/bold] | "
        f"PoV-proven: {pov_proven}/{pov_gated} | Survived hardening: {survived}/{passed} | "
        f"Time: {total_duration:.2f}s | Cost: ${llm_client.get_usage_summary()['estimated_cost_usd']:.4f}\n"
    )
    
    report_dir = PROJECT_ROOT / "reports"
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / "public_benchmarks_report.md"
    
    md = f"""# 🌐 Public Benchmarks Extension Evaluation Report

**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  
**Evaluation Scope:** NIST Juliet Expansion, DARPA CGC MultiOS, Historical CVE Datasets (LibTIFF).

---

## 🏆 Results Table

| Target ID | Suite | CWE | Description | Status | Winning Agent | Hardening | Time (s) |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
"""
    for r in results:
        t = r["target"]
        res = r["result"]
        md += f"| **{t.id}** | {t.suite} | {t.cwe_id} | {t.description} | **{res.status.upper()}** | {res.winning_agent or 'None'} | {r['hardening']} | {res.elapsed_seconds:.2f} |\n"

    md += f"""
---

"""

    md += """---

## 🔬 Per-Target Verification Notes

*Generated from this run's recorded outcomes.*

"""
    for r in results:
        t = r["target"]
        res = r["result"]
        pf = r["preflight"]
        md += f"\n**{t.id}**\n\n"
        md += f"- Pre-flight: {pf.summary()}\n"
        if res is None:
            md += "- Not evaluated (excluded at pre-flight).\n"
            continue
        md += f"- Outcome: **{res.status.upper()}**"
        md += f" (agent: {res.winning_agent})\n" if res.winning_agent else "\n"
        md += f"- Hardening: **{r['hardening']}**\n"
        if r.get("hardening_detail"):
            md += f"    - {r['hardening_detail']}\n"
        if not pf.pov_usable:
            md += ("    - No valid proof-of-vulnerability: this patch is **not**"
                   " dynamically demonstrated to remove the bug.\n")
    md += f"""
---

**Execution Cost:** ${llm_client.get_usage_summary()['estimated_cost_usd']:.4f} USD  
**Total Evaluation Time:** {total_duration:.2f}s  
"""
    report_path.write_text(md)
    console.print(f"📄 Saved Public Benchmarks Report to: [bold]{report_path}[/bold]\n")

if __name__ == "__main__":
    run_public_extension_suite()
