"""
AI Kavach CRS — Audit Report Generator

Every value in the generated report is derived from the actual DRV run:
gate outcomes come from the recorded PatchResult, not from assumption. A gate
that did not run is printed as SKIPPED (with the reason, when the caller
supplies one) and is never rendered as a pass.
"""

import logging
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.agent_orchestrator.orchestrator import PipelineResult
from src.patch_validator.drv_loop import GATE_PASS, GATE_FAIL, GATE_SKIPPED

logger = logging.getLogger(__name__)

_GATE_LABEL = {
    GATE_PASS: "PASS",
    GATE_FAIL: "FAIL",
    GATE_SKIPPED: "SKIPPED (not configured for this target)",
}


class AuditReportGenerator:
    """Generates audit reports summarising findings, patches, and verification."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        results: list[PipelineResult],
        report_name: str = "audit_report",
        gate_notes: dict | None = None,
    ) -> str:
        """
        Generate a Markdown audit report.

        gate_notes: optional {vuln_id: {"pov": reason, "regression": reason}}
        explaining why a gate was not available for that target.
        """
        gate_notes = gate_notes or {}
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_path = (
            self.output_dir / f"{report_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )

        total = len(results)
        patched = sum(1 for r in results if r.status == "patched")
        unresolved = total - patched
        total_time = sum(r.elapsed_seconds for r in results)
        total_cost = sum(r.total_cost_usd for r in results)

        pov_verified = sum(
            1 for r in results
            if r.status == "patched" and self._gate(r, "pov_ok") == GATE_PASS
        )
        regression_verified = sum(
            1 for r in results
            if r.status == "patched" and self._gate(r, "regression_ok") == GATE_PASS
        )

        with open(report_path, "w") as f:
            f.write("# 🛡️ AI Kavach CRS — Automated Vulnerability Remediation Audit Report\n\n")
            f.write(f"**Date:** {timestamp}\n\n")

            f.write("## 1. Executive Summary\n\n")
            f.write(
                "Audit trail of autonomous detection and remediation actions. "
                "Each verification gate below reflects a command that actually "
                "executed during the run; gates with no configured command are "
                "reported as SKIPPED.\n\n"
            )
            f.write("| Metric | Value |\n| :--- | :--- |\n")
            f.write(f"| Total Vulnerabilities Processed | {total} |\n")
            rate = f"{patched / total * 100:.1f}%" if total else "n/a"
            f.write(f"| Patches Passing All Configured Gates | {patched} ({rate}) |\n")
            f.write(f"| — of which proven by PoV replay | {pov_verified} |\n")
            f.write(f"| — of which regression-tested | {regression_verified} |\n")
            f.write(f"| Unresolved / Escalated | {unresolved} |\n")
            f.write(f"| Total Processing Time | {total_time:.2f} seconds |\n")
            f.write(f"| Estimated Compute Cost | ${total_cost:.4f} |\n\n")

            f.write("## 2. Detailed Findings & Remediation\n\n")

            for r in results:
                vuln = r.vulnerability
                icon = {"patched": "✅", "unresolved": "❌"}.get(r.status, "⚠️")
                notes = gate_notes.get(vuln.id, {})

                f.write(f"### {icon} Vulnerability: {vuln.id} ({vuln.cwe_id or 'Unknown CWE'})\n\n")
                f.write("**Metadata:**\n")
                f.write(f"- **Severity:** {vuln.severity.capitalize()}\n")
                f.write(f"- **Location:** `{vuln.file_path}:{vuln.line_number}`\n")
                f.write(f"- **Detection Source:** {vuln.source}\n")
                f.write(f"- **Resolution Status:** {r.status.upper()}\n")
                f.write(f"- **Context Engine:** {r.context_method}\n")
                if r.winning_agent:
                    f.write(f"- **Winning Agent:** {r.winning_agent.capitalize()}\n")
                f.write(f"- **Time Spent:** {r.elapsed_seconds:.2f}s\n")
                f.write(f"- **Cost:** ${r.total_cost_usd:.4f}\n\n")

                f.write("**Description:**\n")
                f.write(f"> {vuln.description}\n\n")

                self._write_agent_table(f, r)

                winning = self._winning_iteration(r)
                if winning:
                    if winning.analysis:
                        f.write("**AI Root Cause Analysis:**\n")
                        f.write(f"{winning.analysis}\n\n")

                    report = r.agent_reports[r.winning_agent]
                    f.write("**Verification (DRV Loop):**\n")
                    f.write(f"- Iterations Required: {report.total_iterations}\n")
                    f.write(f"- Patch Application: {_GATE_LABEL[winning.applied]}\n")
                    f.write(f"- Build Check (ASan+UBSan): {_GATE_LABEL[winning.syntax_ok]}\n")
                    f.write(f"- Proof-of-Vulnerability Replay: {self._gate_line(winning.pov_ok, notes.get('pov'))}\n")
                    f.write(f"- Regression Check: {self._gate_line(winning.regression_ok, notes.get('regression'))}\n")
                    f.write(f"- Post-Patch Static Re-scan: {_GATE_LABEL[winning.post_scan_ok]}\n")
                    f.write(f"- Patch Size: {winning.patch_line_count} changed lines\n\n")

                if r.winning_patch:
                    f.write("**Applied Patch (Unified Diff):**\n")
                    f.write("```diff\n")
                    f.write(f"{r.winning_patch}\n")
                    f.write("```\n\n")
                elif r.status != "patched":
                    f.write("**Attempted Resolution Failed.**\n\n")
                    f.write(self._failure_detail(r))

                f.write("---\n\n")

            f.write("## 3. Scope of Validation\n\n")
            f.write(
                "Patches marked PATCHED passed every gate that was configured and "
                "executed for that target, as itemised above. Where the "
                "Proof-of-Vulnerability gate reads SKIPPED, the fix was **not** "
                "dynamically proven: the target has no reproducible runtime "
                "manifestation on this platform, and only compilation, regression, "
                "and static re-scan evidence support it.\n\n"
            )
            f.write("**Generated by:** AI Kavach Autonomous CRS Engine\n")

        logger.info(f"Audit report generated: {report_path}")
        return str(report_path)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _winning_iteration(r: PipelineResult):
        if not r.winning_agent:
            return None
        report = r.agent_reports.get(r.winning_agent)
        return report.winning_iteration if report else None

    @classmethod
    def _gate(cls, r: PipelineResult, attr: str) -> str:
        it = cls._winning_iteration(r)
        return getattr(it, attr) if it else GATE_SKIPPED

    @staticmethod
    def _gate_line(state: str, note: str | None) -> str:
        if state == GATE_SKIPPED and note:
            return f"SKIPPED — {note}"
        return _GATE_LABEL[state]

    @staticmethod
    def _write_agent_table(f, r: PipelineResult) -> None:
        """Per-agent outcome table — shows what each ensemble member achieved."""
        if not r.agent_reports:
            return
        f.write("**Agent Ensemble:**\n\n")
        f.write("| Agent | Result | Iterations | Failure Stage |\n")
        f.write("| :--- | :--- | ---: | :--- |\n")
        for agent, report in r.agent_reports.items():
            if report is None:
                f.write(f"| {agent.capitalize()} | ERROR | – | agent raised an exception |\n")
                continue
            outcome = "validated" if report.success else "rejected"
            stage = "–" if report.success else (report.last_failure_stage or "unknown")
            f.write(
                f"| {agent.capitalize()} | {outcome} | "
                f"{report.total_iterations}/{report.max_iterations} | {stage} |\n"
            )
        f.write("\n")

    @staticmethod
    def _failure_detail(r: PipelineResult) -> str:
        """Verbatim reason the last attempt was rejected."""
        lines = ["**Rejection reason (final attempt):**\n\n"]
        for agent, report in r.agent_reports.items():
            if report is None or report.success:
                continue
            detail = (report.last_failure or "no feedback recorded").strip()
            lines.append(f"*{agent.capitalize()} — stage `{report.last_failure_stage}`:*\n")
            lines.append("```\n" + detail[:1200] + "\n```\n\n")
        return "".join(lines)
