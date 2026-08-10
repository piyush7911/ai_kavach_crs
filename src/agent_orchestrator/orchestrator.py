"""
AI Kavach CRS — LangGraph Multi-Agent Orchestrator
Coordinates Alpha, Beta, and Gamma agents in parallel DRV loops.
First validated patch wins. If no agent succeeds, vulnerability is UNRESOLVED.
"""

import logging
import time
from typing import Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.agent_orchestrator.llm_client import LLMClient
from src.patch_validator.drv_loop import DRVLoop, DRVReport
from src.memory import MemorySystem

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityReport:
    """A vulnerability to be processed by the orchestrator."""
    id: str
    source: str  # "semgrep", "fuzzer", "manual"
    file_path: str
    line_number: int
    description: str
    cwe_id: str = ""
    severity: str = "medium"
    crash_trace: str = ""
    sarif_context: str = ""
    code_context: str = ""  # Filled by Tree-sitter extractor


@dataclass
class PipelineResult:
    """Result of processing one vulnerability through the full pipeline."""
    vulnerability: VulnerabilityReport
    status: str  # "patched", "unresolved", "error"
    winning_agent: Optional[str] = None
    winning_patch: Optional[str] = None
    agent_reports: dict = field(default_factory=dict)  # {agent_name: DRVReport}
    elapsed_seconds: float = 0.0
    total_cost_usd: float = 0.0   # cost of THIS vulnerability only
    context_extracted: bool = False
    context_method: str = "none"
    recalled_patterns: int = 0

    def summary(self) -> str:
        status_icon = {"patched": "✅", "unresolved": "❌", "error": "⚠️"}.get(self.status, "?")
        return (
            f"{status_icon} [{self.vulnerability.id}] {self.status.upper()} | "
            f"agent={self.winning_agent or 'none'} | "
            f"time={self.elapsed_seconds:.1f}s | "
            f"cost=${self.total_cost_usd:.4f}"
        )


class Orchestrator:
    """
    Multi-agent orchestrator using ensemble strategy.
    Runs Alpha, Beta, Gamma agents in parallel (or sequential) DRV loops.
    """

    # Max DRV iterations per agent
    AGENT_MAX_ITERATIONS = {
        "alpha": 5,
        "beta": 8,
        "gamma": 5,
    }

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        context_extractor=None,
        semgrep_runner=None,
        parallel: bool = True,
        memory: Optional[MemorySystem] = None,
    ):
        self.llm_client = llm_client or LLMClient()
        self.context_extractor = context_extractor
        self.semgrep_runner = semgrep_runner
        self.parallel = parallel
        # Cross-target memory. Disabled by default so a benchmark run is
        # reproducible unless memory is explicitly requested.
        self.memory = memory
        self.drv_loop = DRVLoop(
            llm_client=self.llm_client,
            context_extractor=context_extractor,
            semgrep_runner=semgrep_runner,
        )

    def process_vulnerability(
        self,
        vuln: VulnerabilityReport,
        build_command: Optional[str] = None,
        test_command: Optional[str] = None,
        pov_command: Optional[str] = None,
        agents: Optional[list[str]] = None,
        source_dir: Optional[str] = None,
    ) -> PipelineResult:
        """
        Process a single vulnerability through the multi-agent ensemble.

        Args:
            vuln: The vulnerability to process.
            build_command: Shell command to build the project after patching.
            test_command: Shell command to run regression tests.
            pov_command: Shell command to run the proof-of-vulnerability.
            agents: List of agents to use. Default: ["alpha", "beta", "gamma"].

        Returns:
            PipelineResult with the outcome.
        """
        agents = agents or ["alpha", "beta", "gamma"]
        start_time = time.time()
        cost_before = self.llm_client.get_usage_summary()["estimated_cost_usd"]

        logger.info(f"Processing vulnerability: {vuln.id} ({vuln.cwe_id})")

        # Enrich context with Tree-sitter if available
        context_extracted, context_method = False, "none"
        if self.context_extractor and not vuln.code_context:
            try:
                ctx = self.context_extractor.extract_context(
                    vuln.file_path, vuln.line_number
                )
                vuln.code_context = ctx["full_context"]
                context_extracted = bool(ctx["full_context"])
                context_method = ctx["extraction_method"]
                logger.info(
                    f"Extracted context: {ctx['function_name']} "
                    f"({ctx['extraction_method']})"
                )
            except Exception as e:
                logger.warning(f"Context extraction failed: {e}")
                context_method = f"failed: {e}"

        # Semantic recall: validated fixes for similar bugs solved before.
        recalled = []
        if self.memory:
            crash_class = self._crash_class(vuln)
            recalled = self.memory.recall_for(vuln.cwe_id, crash_class, vuln.description)

        # Build the vulnerability context string for LLM
        vuln_context = self._build_vulnerability_prompt(vuln)
        if recalled:
            vuln_context += "\n\n" + self.memory.semantic.render_for_prompt(recalled)
            logger.info(f"Recalled {len(recalled)} validated fix pattern(s) from memory")

        runner = self._run_parallel if (self.parallel and len(agents) > 1) else self._run_sequential
        result = runner(
            agents, vuln, vuln_context,
            build_command, test_command, pov_command, source_dir,
        )

        result.elapsed_seconds = time.time() - start_time
        # Per-vulnerability cost, not the running total.
        result.total_cost_usd = round(
            self.llm_client.get_usage_summary()["estimated_cost_usd"] - cost_before, 6
        )
        result.context_extracted = context_extracted
        result.context_method = context_method
        result.recalled_patterns = len(recalled)

        if self.memory:
            self._update_memory(vuln, result, recalled)

        logger.info(result.summary())
        return result

    @staticmethod
    def _crash_class(vuln: VulnerabilityReport) -> str:
        """Crash class from the sanitizer trace, when the bug came from fuzzing."""
        trace = (vuln.crash_trace or "") + " " + (vuln.description or "")
        for known in (
            "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
            "heap-use-after-free", "double-free", "memcpy-param-overlap",
            "SEGV", "out of bounds", "allocation size",
        ):
            if known.lower() in trace.lower():
                return known
        return ""

    def _update_memory(self, vuln, result, recalled) -> None:
        """
        Write back what was learned.

        Only *validated* outcomes become semantic memory: a fix is remembered
        because gates proved it works, never because an agent believed it did.
        Pitfalls are stored as observations attached to the successful pattern,
        so a wrong inference cannot become a standing rule.
        """
        report = result.agent_reports.get(result.winning_agent) if result.winning_agent else None
        winning = report.winning_iteration if report else None

        self.memory.episodic.record({
            "vulnerability_id": vuln.id,
            "cwe": vuln.cwe_id,
            "file": vuln.file_path,
            "status": result.status,
            "winning_agent": result.winning_agent,
            "elapsed_seconds": round(result.elapsed_seconds, 2),
            "cost_usd": result.total_cost_usd,
            "recalled_patterns": len(recalled),
            "attempts": [
                {"agent": a.agent, "rejected_by": a.rejected_by,
                 "critic": a.critic_verdict, "summary": a.summary}
                for r in result.agent_reports.values() if r
                for a in getattr(r, "attempt_ledger", [])
            ],
        })

        succeeded = result.status == "patched"
        self.memory.procedural.record(
            vuln.cwe_id, result.winning_agent,
            report.total_iterations if report else 0, succeeded,
        )
        # Confidence tracks reality: a recalled pattern that did not lead to a
        # fix loses influence.
        self.memory.semantic.record_outcome(recalled, succeeded)

        if succeeded and winning:
            pitfalls = [
                f"rejected by {a.rejected_by} gate: {a.summary}"
                for r in result.agent_reports.values() if r
                for a in getattr(r, "attempt_ledger", [])
            ][:4]
            self.memory.learn_from(
                target_id=vuln.id,
                cwe=vuln.cwe_id,
                crash_class=self._crash_class(vuln),
                root_cause=(winning.analysis or vuln.description)[:400],
                fix_strategy=(result.winning_patch or "")[:600],
                pitfalls=pitfalls,
                winning_agent=result.winning_agent or "",
                iterations=report.total_iterations if report else 0,
                hardened=False,   # set later by the benchmark if hardening passes
            )

    def _run_parallel(
        self, agents, vuln, vuln_context,
        build_command, test_command, pov_command, source_dir=None,
    ) -> PipelineResult:
        """Run all agents in parallel. Among the winners, prefer the smallest patch."""
        result = PipelineResult(vulnerability=vuln, status="unresolved")

        with ThreadPoolExecutor(max_workers=len(agents)) as executor:
            futures = {}
            for agent in agents:
                future = executor.submit(
                    self.drv_loop.run,
                    agent_name=agent,
                    vulnerability_context=vuln_context,
                    target_file=vuln.file_path,
                    max_iterations=self.AGENT_MAX_ITERATIONS.get(agent, 5),
                    vulnerability_id=vuln.id,
                    build_command=build_command,
                    test_command=test_command,
                    pov_command=pov_command,
                    source_dir=source_dir,
                )
                futures[future] = agent

            for future in as_completed(futures):
                agent = futures[future]
                try:
                    result.agent_reports[agent] = future.result()
                except Exception as e:
                    logger.error(f"Agent {agent} failed with error: {e}")
                    result.agent_reports[agent] = None

        self._select_winner(result, agents)
        return result

    def _run_sequential(
        self, agents, vuln, vuln_context,
        build_command, test_command, pov_command, source_dir=None,
    ) -> PipelineResult:
        """Run agents sequentially. Stop at first validated patch."""
        result = PipelineResult(vulnerability=vuln, status="unresolved")

        for agent in agents:
            try:
                report = self.drv_loop.run(
                    agent_name=agent,
                    vulnerability_context=vuln_context,
                    target_file=vuln.file_path,
                    max_iterations=self.AGENT_MAX_ITERATIONS.get(agent, 5),
                    vulnerability_id=vuln.id,
                    build_command=build_command,
                    test_command=test_command,
                    pov_command=pov_command,
                    source_dir=source_dir,
                )
                result.agent_reports[agent] = report
                if report.success:
                    break
            except Exception as e:
                logger.error(f"Agent {agent} failed with error: {e}")
                result.agent_reports[agent] = None

        self._select_winner(result, agents)
        return result

    @staticmethod
    def _select_winner(result: PipelineResult, agents: list[str]) -> None:
        """
        Pick the winning agent among those whose patch passed every gate.
        Tie-break on the smallest validated patch (minimal-change principle),
        then on agent order for determinism.
        """
        winners = [
            (agent, report) for agent in agents
            if (report := result.agent_reports.get(agent)) is not None and report.success
        ]
        if not winners:
            return

        def patch_size(item):
            agent, report = item
            it = report.winning_iteration
            return (it.patch_line_count if it else 10**6, agents.index(agent))

        agent, report = min(winners, key=patch_size)
        result.status = "patched"
        result.winning_agent = agent
        result.winning_patch = report.winning_patch
        logger.info(
            f"🏆 Agent {agent} produced the winning patch "
            f"({len(winners)} of {len(agents)} agents validated)"
        )

    @staticmethod
    def _build_vulnerability_prompt(vuln: VulnerabilityReport) -> str:
        """Build the vulnerability context string for the LLM."""
        parts = []

        parts.append(f"VULNERABILITY ID: {vuln.id}")
        parts.append(f"SOURCE: {vuln.source}")
        parts.append(f"FILE: {vuln.file_path}")
        parts.append(f"LINE: {vuln.line_number}")

        if vuln.cwe_id:
            parts.append(f"CWE: {vuln.cwe_id}")

        parts.append(f"SEVERITY: {vuln.severity}")
        parts.append(f"\nDESCRIPTION:\n{vuln.description}")

        if vuln.crash_trace:
            parts.append(f"\nCRASH TRACE:\n{vuln.crash_trace}")

        if vuln.sarif_context:
            parts.append(f"\nSARIF FINDING:\n{vuln.sarif_context}")

        if vuln.code_context:
            parts.append(f"\nSOURCE CODE CONTEXT:\n{vuln.code_context}")

        return "\n".join(parts)

    def process_batch(
        self,
        vulnerabilities: list[VulnerabilityReport],
        build_command: Optional[str] = None,
        test_command: Optional[str] = None,
        pov_command: Optional[str] = None,
        source_dir: Optional[str] = None,
    ) -> list[PipelineResult]:
        """Process a batch of vulnerabilities sequentially."""
        results = []
        for i, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"\n{'='*60}")
            logger.info(f"Processing vulnerability {i}/{len(vulnerabilities)}")
            logger.info(f"{'='*60}")
            result = self.process_vulnerability(
                vuln, build_command, test_command, pov_command, source_dir=source_dir
            )
            results.append(result)

        # Print summary
        patched = sum(1 for r in results if r.status == "patched")
        total = len(results)
        logger.info(f"\n{'='*60}")
        logger.info(f"BATCH COMPLETE: {patched}/{total} vulnerabilities patched")
        logger.info(f"{'='*60}")

        return results
