"""
AI Kavach CRS — Discovery pipeline: fuzz → triage → patch → verify.

This is the end-to-end loop the architecture describes, with no step assumed:

  1. **Fuzz.** Build the target with a libFuzzer-style harness under ASan+UBSan
     and run a real campaign (libFuzzer or AFL++). Crashes are files on disk.
  2. **Triage.** Replay each crash, parse the sanitizer report, and cluster by
     root cause so N crashing inputs become one vulnerability per bug.
  3. **Locate.** The crash's own stack trace supplies file and line — the
     location is *discovered*, not declared in advance.
  4. **Patch & verify.** Hand the located vulnerability to the agent ensemble
     and run it through the DRV gates, replaying the discovered crash input as
     the proof-of-vulnerability.

The PoV in step 4 is the fuzzer's own crashing input, so a patch passes only if
the exact input that crashed the program no longer does.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.analysis_engine.fuzzer_manager import FuzzerManager, FuzzCampaignResult
from src.analysis_engine.crash_triage import CrashTriage, CrashCluster
from src.agent_orchestrator.orchestrator import Orchestrator, PipelineResult

logger = logging.getLogger(__name__)

# Absolute: the DRV loop runs gate commands with cwd set to a temporary
# workspace, so any relative path here would silently fail to resolve and be
# recorded as a PoV failure rather than a broken command.
HARNESS_DIR = Path("tests/fuzz_harnesses").resolve()


@dataclass
class DiscoveryResult:
    """What one target's discovery campaign produced. All values observed."""

    target_id: str
    source_file: str
    campaign: Optional[FuzzCampaignResult] = None
    clusters: list[CrashCluster] = field(default_factory=list)
    patch_results: list[PipelineResult] = field(default_factory=list)
    error: str = ""

    @property
    def crashes_found(self) -> int:
        return self.campaign.crash_count if self.campaign else 0

    @property
    def unique_bugs(self) -> int:
        return len(self.clusters)

    @property
    def patched(self) -> int:
        return sum(1 for r in self.patch_results if r.status == "patched")


class FuzzDiscoveryPipeline:
    """Runs fuzz → triage → patch → verify for harnessed targets."""

    def __init__(
        self,
        orchestrator: Orchestrator,
        workspace: str = "benchmark_workspace/fuzzing",
        engine: str = "libfuzzer",
        source_root: str = "tests/demo_vulns",
    ):
        self.orchestrator = orchestrator
        self.fuzzer = FuzzerManager(workspace, harness_dir=str(HARNESS_DIR))
        self.triage = CrashTriage(f"{workspace}/triage", source_root=source_root)
        self.engine = engine

    @staticmethod
    def harnessed_targets() -> list[str]:
        """Target ids that have a fuzz harness checked in."""
        if not HARNESS_DIR.exists():
            return []
        return sorted(
            p.stem for p in HARNESS_DIR.glob("*.c") if p.stem != "afl_driver"
        )

    def run(
        self,
        target_id: str,
        source_file: str,
        build_command: str,
        regression_command: Optional[str] = None,
        seconds: int = 30,
    ) -> DiscoveryResult:
        """Discover, triage, then patch and verify every distinct bug found."""
        result = DiscoveryResult(target_id=target_id, source_file=source_file)

        # 1 — fuzz
        campaign = self.fuzzer.run_campaign(
            target_id, source_file, engine=self.engine, seconds=seconds
        )
        result.campaign = campaign
        if not campaign.build_ok:
            result.error = f"fuzz build failed: {campaign.build_error[:300]}"
            return result
        if not campaign.crashes:
            logger.info(f"[{target_id}] no crashes found in {seconds}s — nothing to patch")
            return result

        # 2/3 — triage and locate
        result.clusters = self.triage.triage(campaign.binary, campaign.crashes, args=["@@"])
        vulnerabilities = self.triage.to_vulnerability_reports(result.clusters)
        if not vulnerabilities:
            result.error = "crashes found but none reproduced during triage"
            return result

        # 4 — patch each distinct bug, gated on its own discovered crash input
        for vuln, cluster in zip(vulnerabilities, result.clusters):
            if not vuln.file_path or not Path(vuln.file_path).exists():
                logger.warning(f"[{target_id}] {vuln.id}: crash location unresolved, skipping")
                continue

            vuln.id = f"{target_id}::{vuln.id}"
            pov = self._pov_command(campaign.binary, cluster.representative)

            result.patch_results.append(self.orchestrator.process_vulnerability(
                vuln,
                build_command=build_command,
                pov_command=pov,
                test_command=regression_command,
            ))

        return result

    @staticmethod
    def _pov_command(fuzz_binary: str, crash_input: str) -> str:
        """
        PoV gate for a fuzzer-discovered bug.

        The patched source is rebuilt into the fuzz harness and replayed on the
        crashing input; exit 0 (no sanitizer report) means the bug is fixed.
        `{src}` is substituted by the DRV loop with the patched file, so this
        genuinely tests the patch rather than the original binary.
        """
        harness = Path(fuzz_binary).parent.parent.name
        harness_source = HARNESS_DIR / f"{harness}.c"
        driver = HARNESS_DIR / "afl_driver.c"
        crash_input = str(Path(crash_input).resolve())
        pov_runner = (HARNESS_DIR.parent / "benchmarks" / "harness" / "pov_run.sh").resolve()
        rebuilt = "{workspace}/pov_target"
        mangled = harness.replace("-", "_")
        return (
            f'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 '
            f'-Dmain=kavach_disabled_main_{mangled} -c "{{src}}" -o "{{workspace}}/tgt.o" && '
            f'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 '
            f'-c "{harness_source}" -o "{{workspace}}/harness.o" && '
            f'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 '
            f'-c "{driver}" -o "{{workspace}}/driver.o" && '
            f'clang -fsanitize=address,undefined -fno-sanitize-recover=all '
            f'"{{workspace}}/tgt.o" "{{workspace}}/harness.o" "{{workspace}}/driver.o" '
            f'-o "{rebuilt}" && '
            f'sh "{pov_runner}" "{rebuilt}" "{crash_input}"'
        )
