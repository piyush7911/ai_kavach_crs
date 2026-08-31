"""
Tests for ensemble winner selection.

`_select_winner` decides which patch the system actually reports, out of up to
three that each cleared every gate. It is pure, deterministic and needs no API
call, so there is no reason for it to be untested — it was, until now.

Two properties matter and neither is obvious from reading it:
  * a failed agent can never win, however small its patch;
  * the choice is stable across runs, because agents finish in nondeterministic
    order under the thread pool.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.agent_orchestrator.orchestrator import Orchestrator, PipelineResult, VulnerabilityReport
from src.patch_validator.drv_loop import DRVReport, PatchResult

AGENTS = ["alpha", "beta", "gamma"]


def _report(agent: str, success: bool, patch_lines: int, patch: str = "") -> DRVReport:
    """A DRVReport whose winning iteration has a known patch size."""
    rep = DRVReport(
        agent_name=agent, vulnerability_id="T", total_iterations=1,
        max_iterations=5, success=success, winning_patch=patch or f"{agent}-patch",
    )
    it = PatchResult(iteration=1, agent_name=agent, patch_diff=patch or f"{agent}-patch")
    it.patch_line_count = patch_lines
    it.fully_validated = success
    rep.iterations.append(it)
    return rep


def _result(**reports) -> PipelineResult:
    vuln = VulnerabilityReport(
        id="T", source="test", file_path="x.c", line_number=1,
        description="d", cwe_id="CWE-125", severity="critical",
    )
    res = PipelineResult(vulnerability=vuln, status="unresolved")
    res.agent_reports = dict(reports)
    return res


def test_smallest_validated_patch_wins():
    res = _result(
        alpha=_report("alpha", True, 40),
        beta=_report("beta", True, 3),
        gamma=_report("gamma", True, 12),
    )
    Orchestrator._select_winner(res, AGENTS)
    assert res.status == "patched"
    assert res.winning_agent == "beta", "minimal-change principle not applied"


def test_a_failed_agent_never_wins_however_small_its_patch():
    """The whole point of the gates: size is a tie-break among winners only."""
    res = _result(
        alpha=_report("alpha", False, 1),     # tiny, but did not pass the gates
        gamma=_report("gamma", True, 99),
    )
    Orchestrator._select_winner(res, AGENTS)
    assert res.winning_agent == "gamma"
    assert res.winning_patch == "gamma-patch"


def test_no_winner_leaves_status_unresolved():
    res = _result(
        alpha=_report("alpha", False, 1),
        beta=_report("beta", False, 1),
    )
    Orchestrator._select_winner(res, AGENTS)
    assert res.status == "unresolved"
    assert res.winning_agent is None


def test_ties_break_on_agent_order_not_completion_order():
    """
    Agents finish in nondeterministic order under the thread pool. Equal-sized
    patches must still select the same agent every run, or the reported patch
    changes between identical runs.
    """
    for ordering in ([("alpha", "gamma")], [("gamma", "alpha")]):
        (first, second), = ordering
        res = _result(**{
            first: _report(first, True, 7),
            second: _report(second, True, 7),
        })
        Orchestrator._select_winner(res, AGENTS)
        assert res.winning_agent == "alpha", "tie-break must follow AGENTS order"


def test_crashed_agent_recorded_as_none_is_skipped():
    """`_run_parallel` stores None when an agent raises; that must not crash selection."""
    res = _result(alpha=None, beta=_report("beta", True, 5))
    Orchestrator._select_winner(res, AGENTS)
    assert res.winning_agent == "beta"


def test_agent_absent_from_reports_is_skipped():
    res = _result(beta=_report("beta", True, 5))
    Orchestrator._select_winner(res, AGENTS)
    assert res.winning_agent == "beta"
