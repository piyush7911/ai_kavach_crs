"""
AI Kavach CRS — Main Entry Point
Run the full vulnerability analysis and patching pipeline.
"""

import sys
import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_llm_config
from src.context_engine.tree_sitter_extractor import ContextExtractor
from src.analysis_engine.semgrep_runner import SemgrepRunner, SarifFinding
from src.agent_orchestrator.llm_client import LLMClient
from src.agent_orchestrator.orchestrator import Orchestrator, VulnerabilityReport
from src.reporting.audit_report import AuditReportGenerator

console = Console()


def setup_logging(verbose: bool = False):
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def print_banner():
    """Print the AI Kavach banner."""
    banner = """
╔══════════════════════════════════════════════════╗
║           🛡️  AI KAVACH CRS  🛡️                  ║
║     Autonomous Cyber Reasoning System            ║
║     Indian Army Terrier Cyber Quest 2026         ║
╠══════════════════════════════════════════════════╣
║  Detect → Repair → Verify                       ║
║  Multi-Agent LLM Ensemble + DRV Loop             ║
╚══════════════════════════════════════════════════╝
    """
    console.print(Panel(banner.strip(), style="bold cyan"))


def _gates_summary(result) -> str:
    """Compact list of the verification gates that actually ran for a target."""
    report = result.agent_reports.get(result.winning_agent) if result.winning_agent else None
    winning = report.winning_iteration if report else None
    if not winning:
        return "—"
    gates = winning.executed_gates
    return "+".join(gates) if gates else "none (unverified)"


def run_pipeline(
    target_path: str,
    language: str = "c",
    build_command: str = None,
    test_command: str = None,
    pov_command: str = None,
    agents: list[str] = None,
    sequential: bool = False,
):
    """Run the full AI Kavach pipeline on a target."""

    # Step 1: Initialize components
    console.print("\n[bold blue]Step 1:[/] Initializing components...")

    try:
        config = get_llm_config()
        console.print(f"  ✅ API key loaded (model: {config['models']['alpha']})")
    except ValueError as e:
        console.print(f"  ❌ {e}", style="red")
        sys.exit(1)

    llm_client = LLMClient()
    context_extractor = ContextExtractor()

    # Try to initialize Semgrep (optional)
    semgrep_runner = None
    try:
        semgrep_runner = SemgrepRunner()
        console.print("  ✅ Semgrep available")
    except RuntimeError:
        console.print("  ⚠️  Semgrep not installed (static analysis disabled)")

    orchestrator = Orchestrator(
        llm_client=llm_client,
        context_extractor=context_extractor,
        semgrep_runner=semgrep_runner,
        parallel=not sequential,
    )

    # Step 2: Static Analysis (Semgrep)
    console.print("\n[bold blue]Step 2:[/] Running static analysis...")
    sarif_findings: list[SarifFinding] = []

    target = Path(target_path)
    if not target.exists():
        console.print(f"  ❌ Target not found: {target_path}", style="red")
        sys.exit(1)

    if semgrep_runner:
        try:
            sarif_findings = semgrep_runner.scan(str(target))
            console.print(f"  📋 Found {len(sarif_findings)} SARIF findings")
            for f in sarif_findings[:5]:
                console.print(
                    f"    • [{f.severity}] {f.rule_id} at {f.file_path}:{f.start_line}"
                    f" (CWE: {', '.join(f.cwe_ids) or 'N/A'})"
                )
            if len(sarif_findings) > 5:
                console.print(f"    ... and {len(sarif_findings) - 5} more")
        except Exception as e:
            console.print(f"  ⚠️  Semgrep scan failed: {e}")

    # Step 3: Convert findings to VulnerabilityReports
    console.print("\n[bold blue]Step 3:[/] Preparing vulnerability reports...")
    vulnerabilities: list[VulnerabilityReport] = []

    for i, finding in enumerate(sarif_findings):
        vuln = VulnerabilityReport(
            id=f"SARIF-{i+1:03d}",
            source="semgrep",
            file_path=str(target / finding.file_path) if target.is_dir() else str(target),
            line_number=finding.start_line,
            description=finding.message,
            cwe_id=finding.cwe_ids[0] if finding.cwe_ids else "",
            severity=finding.severity,
            sarif_context=finding.to_prompt_context(),
        )
        vulnerabilities.append(vuln)

    if not vulnerabilities:
        console.print("  ℹ️  No vulnerabilities found via static analysis.")
        console.print("  💡 You can add manual vulnerability reports or run fuzzing.")
        return

    console.print(f"  📊 {len(vulnerabilities)} vulnerabilities queued for patching")

    # Step 4: Run the multi-agent ensemble
    console.print("\n[bold blue]Step 4:[/] Running multi-agent patching ensemble...")
    agent_list = agents or ["alpha", "beta", "gamma"]
    console.print(f"  Agents: {', '.join(agent_list)}")
    console.print(f"  Mode: {'sequential' if sequential else 'parallel'}")

    if not build_command:
        console.print(
            "  [yellow]No --build-cmd given: the compile gate will be SKIPPED and "
            "patches will not be verified to compile.[/]"
        )
    if not pov_command:
        console.print(
            "  [yellow]No --pov-cmd given: the proof-of-vulnerability gate will be "
            "SKIPPED. Patches cannot be shown to actually fix the bug.[/]"
        )

    results = []
    for vuln in vulnerabilities:
        results.append(orchestrator.process_vulnerability(
            vuln,
            build_command=build_command,
            test_command=test_command,
            pov_command=pov_command,
            agents=agent_list,
        ))

    # Step 5: Print results
    console.print("\n[bold blue]Step 5:[/] Results")

    table = Table(title="AI Kavach CRS — Patch Results")
    table.add_column("ID", style="cyan")
    table.add_column("CWE", style="yellow")
    table.add_column("File", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Agent", style="magenta")
    table.add_column("Time", style="green")
    table.add_column("Cost", style="blue")

    table.add_column("Gates", style="white")

    for r in results:
        status_style = "green" if r.status == "patched" else "red"
        table.add_row(
            r.vulnerability.id,
            r.vulnerability.cwe_id or "—",
            f"{Path(r.vulnerability.file_path).name}:{r.vulnerability.line_number}",
            f"[{status_style}]{r.status.upper()}[/{status_style}]",
            r.winning_agent or "—",
            f"{r.elapsed_seconds:.1f}s",
            f"${r.total_cost_usd:.4f}",
            _gates_summary(r),
        )

    console.print(table)

    # Summary
    patched = sum(1 for r in results if r.status == "patched")
    total = len(results)
    usage = llm_client.get_usage_summary()

    console.print(
        f"\n[bold]Summary:[/] {patched}/{total} passed every gate that was configured"
    )
    console.print(
        "  [dim]'Gates' lists the checks that actually ran for each target. "
        "A patch with no build/pov gate is unverified.[/]"
    )
    console.print(f"  Total API calls: {usage['total_calls']}")
    console.print(f"  Total tokens: {usage['total_input_tokens']:,} in / {usage['total_output_tokens']:,} out")
    console.print(f"  Estimated cost: ${usage['estimated_cost_usd']:.4f}")

    # Output patches
    if patched > 0:
        console.print("\n[bold green]Generated Patches:[/]")
        for r in results:
            if r.winning_patch:
                console.print(f"\n--- {r.vulnerability.id} ({r.winning_agent}) ---")
                console.print(r.winning_patch)

    # Generate Audit Report
    console.print("\n[bold blue]Step 6:[/] Generating Audit Report...")
    report_gen = AuditReportGenerator(output_dir="reports")
    report_path = report_gen.generate_report(results)
    console.print(f"  📄 Saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="AI Kavach CRS — Autonomous Cyber Reasoning System"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Path to target file or directory to analyze"
    )
    parser.add_argument(
        "--language", "-l",
        default="c",
        choices=["c", "cpp"],
        help="Target language (default: c)"
    )
    parser.add_argument(
        "--build-cmd",
        help="Build command to compile the project (e.g., 'make')"
    )
    parser.add_argument(
        "--test-cmd",
        help="Test command to run regression tests"
    )
    parser.add_argument(
        "--pov-cmd",
        help=(
            "Proof-of-vulnerability command. Must exit 0 only when the "
            "vulnerability is NOT present. Without it, patches cannot be shown "
            "to actually fix the bug. Supports {src}/{srcdir}/{bin}/{workspace}."
        )
    )
    parser.add_argument(
        "--agents",
        nargs="+",
        default=["alpha", "beta", "gamma"],
        choices=["alpha", "beta", "gamma"],
        help="Agents to use (default: all three)"
    )
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Run agents sequentially instead of in parallel"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    print_banner()

    run_pipeline(
        target_path=args.target,
        language=args.language,
        build_command=args.build_cmd,
        test_command=args.test_cmd,
        pov_command=args.pov_cmd,
        agents=args.agents,
        sequential=args.sequential,
    )


if __name__ == "__main__":
    main()
