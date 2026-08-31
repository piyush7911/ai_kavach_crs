"""
Tests for the audit report generator.

This module is where the project's original fabricated results came from: the
previous version printed "Build Check: PASS / PoV Check: PASS / Regression
Check: PASS" for every target, including targets that had no build, PoV or
regression command configured at all. The rendering is now driven entirely by
the recorded PatchResult, and these tests pin that.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.agent_orchestrator.orchestrator import PipelineResult, VulnerabilityReport
from src.patch_validator.drv_loop import DRVReport, PatchResult, GATE_PASS, GATE_SKIPPED
from src.reporting.audit_report import AuditReportGenerator


def _result(pov_state: str, build_state: str = GATE_PASS) -> PipelineResult:
    vuln = VulnerabilityReport(
        id="T-1", source="test", file_path="x.c", line_number=1,
        description="d", cwe_id="CWE-125", severity="critical",
    )
    it = PatchResult(iteration=1, agent_name="beta", patch_diff="+ guard")
    it.syntax_ok = build_state
    it.pov_ok = pov_state
    it.regression_ok = GATE_SKIPPED
    it.fully_validated = True
    rep = DRVReport(agent_name="beta", vulnerability_id="T-1", total_iterations=1,
                    max_iterations=5, success=True, winning_patch="+ guard")
    rep.iterations.append(it)

    res = PipelineResult(vulnerability=vuln, status="patched")
    res.winning_agent = "beta"
    res.winning_patch = "+ guard"
    res.agent_reports = {"beta": rep}
    return res


def test_skipped_pov_is_never_rendered_as_pass(tmp_path):
    """The exact defect that produced this project's fabricated results."""
    gen = AuditReportGenerator(output_dir=str(tmp_path))
    path = gen.generate_report([_result(GATE_SKIPPED)], report_name="t")
    body = Path(path).read_text()

    assert "SKIPPED" in body
    # The report must not claim the exploit was replayed when it never was.
    assert "PoV Check: PASS" not in body
    assert "Proof-of-Vulnerability: PASS" not in body


def test_a_skipped_pov_is_not_counted_as_dynamically_proven(tmp_path):
    gen = AuditReportGenerator(output_dir=str(tmp_path))
    skipped = Path(gen.generate_report([_result(GATE_SKIPPED)], report_name="s")).read_text()
    proven = Path(gen.generate_report([_result(GATE_PASS)], report_name="p")).read_text()
    assert skipped != proven, "a skipped PoV renders identically to a proven one"


def test_gate_note_is_surfaced_when_supplied(tmp_path):
    gen = AuditReportGenerator(output_dir=str(tmp_path))
    path = gen.generate_report(
        [_result(GATE_SKIPPED)], report_name="n",
        gate_notes={"T-1": {"pov": "requires MemorySanitizer (Linux only)"}},
    )
    assert "MemorySanitizer" in Path(path).read_text(), (
        "the reason a gate could not run must reach the report"
    )
