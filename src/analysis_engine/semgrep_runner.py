"""
AI Kavach CRS — Semgrep Static Analysis Runner
Runs Semgrep on target code and parses SARIF output into structured vulnerability reports.
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SarifFinding:
    """A single vulnerability finding from Semgrep SARIF output."""
    rule_id: str
    message: str
    severity: str  # "error", "warning", "note"
    file_path: str
    start_line: int
    end_line: int
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    confidence: str = "medium"
    snippet: str = ""

    def to_prompt_context(self) -> str:
        """Format this finding as context for an LLM agent."""
        cwe_str = ", ".join(self.cwe_ids) if self.cwe_ids else "Unknown"
        return (
            f"SARIF FINDING:\n"
            f"  Rule: {self.rule_id}\n"
            f"  Severity: {self.severity}\n"
            f"  CWE: {cwe_str}\n"
            f"  File: {self.file_path}\n"
            f"  Lines: {self.start_line}-{self.end_line}\n"
            f"  Message: {self.message}\n"
            f"  Code Snippet:\n{self.snippet}\n"
        )


class SemgrepRunner:
    """
    Runs Semgrep CLI on target code and parses SARIF v2.1.0 output.
    """

    def __init__(self, rules: str = "p/security-audit"):
        """
        Args:
            rules: Semgrep rule config. Default is the security-audit pack.
                   Can be a path to custom rules YAML or a registry reference.
        """
        self.rules = rules
        self._check_semgrep_installed()

    @staticmethod
    def _check_semgrep_installed():
        """Verify semgrep CLI is available."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Semgrep version: {result.stdout.strip()}")
            else:
                raise RuntimeError("Semgrep returned non-zero exit code")
        except FileNotFoundError:
            raise RuntimeError(
                "Semgrep not found. Install with: pip install semgrep"
            )

    def scan(
        self,
        target_path: str,
        max_findings: int = 100,
        timeout: int = 300,
    ) -> list[SarifFinding]:
        """
        Run Semgrep on the target path and return parsed findings.

        Args:
            target_path: Path to file or directory to scan.
            max_findings: Maximum number of findings to return.
            timeout: Maximum scan time in seconds.

        Returns:
            List of SarifFinding objects, sorted by severity (error first).
        """
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        # Run semgrep with SARIF output
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            sarif_path = f.name

        try:
            cmd = [
                "semgrep", "scan",
                "--config", self.rules,
                "--sarif",
                "--output", sarif_path,
                "--quiet",
                "--no-git-ignore",
                str(target),
            ]

            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode not in (0, 1):  # 1 = findings found (expected)
                logger.warning(f"Semgrep stderr: {result.stderr}")

            # Parse SARIF output
            findings = self._parse_sarif(sarif_path, target_path)

            # Sort by severity
            severity_order = {"error": 0, "warning": 1, "note": 2}
            findings.sort(key=lambda f: severity_order.get(f.severity, 3))

            return findings[:max_findings]

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out after {timeout}s")
            return []
        finally:
            Path(sarif_path).unlink(missing_ok=True)

    def _parse_sarif(self, sarif_path: str, base_path: str) -> list[SarifFinding]:
        """Parse SARIF v2.1.0 JSON into SarifFinding objects."""
        try:
            with open(sarif_path, "r") as f:
                sarif = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to parse SARIF: {e}")
            return []

        findings = []
        for run in sarif.get("runs", []):
            # Build rule lookup for CWE/OWASP mappings
            rule_map = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id", "")
                cwe_ids = []
                owasp_ids = []
                for tag in rule.get("properties", {}).get("tags", []):
                    if tag.startswith("CWE-"):
                        cwe_ids.append(tag)
                    elif tag.startswith("OWASP"):
                        owasp_ids.append(tag)
                rule_map[rule_id] = {
                    "cwe_ids": cwe_ids,
                    "owasp_ids": owasp_ids,
                    "confidence": rule.get("properties", {}).get("precision", "medium"),
                }

            # Parse results
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule_info = rule_map.get(rule_id, {})

                # Get location
                locations = result.get("locations", [])
                if not locations:
                    continue

                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})

                # Get code snippet if available
                snippet = ""
                context_region = phys.get("contextRegion", {})
                if context_region:
                    snippet_obj = context_region.get("snippet", {})
                    snippet = snippet_obj.get("text", "")
                elif region:
                    snippet_obj = region.get("snippet", {})
                    snippet = snippet_obj.get("text", "")

                findings.append(SarifFinding(
                    rule_id=rule_id,
                    message=result.get("message", {}).get("text", ""),
                    severity=result.get("level", "warning"),
                    file_path=artifact,
                    start_line=region.get("startLine", 0),
                    end_line=region.get("endLine", region.get("startLine", 0)),
                    cwe_ids=rule_info.get("cwe_ids", []),
                    owasp_ids=rule_info.get("owasp_ids", []),
                    confidence=rule_info.get("confidence", "medium"),
                    snippet=snippet,
                ))

        logger.info(f"Parsed {len(findings)} findings from SARIF")
        return findings

    def scan_file(self, file_path: str) -> list[SarifFinding]:
        """Convenience method to scan a single file."""
        return self.scan(file_path)

    def scan_directory(self, dir_path: str) -> list[SarifFinding]:
        """Convenience method to scan a directory."""
        return self.scan(dir_path)
