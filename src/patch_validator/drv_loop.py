"""
AI Kavach CRS — DRV (Detect-Repair-Verify) Loop
Implements the iterative patch validation feedback loop.

Each iteration builds an isolated workspace, applies the agent's patch to it,
compiles it, and runs the proof-of-vulnerability and regression gates against
the freshly built PATCHED binary. Failures are fed back verbatim to the agent
as context for the next iteration.

Gate semantics
--------------
Every gate reports one of three states and the state is recorded, never assumed:

    GATE_PASS     the command ran and exited 0
    GATE_FAIL     the command ran and exited non-zero (feedback goes to the agent)
    GATE_SKIPPED  no command was configured for this target

A patch is `fully_validated` only if no gate FAILED. `verified_gates` records
exactly which gates actually executed, so downstream reporting can distinguish
"PoV proved the fix" from "no PoV existed for this target".
"""

import difflib
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from src.agent_orchestrator.critic import Critic, EscalationPolicy
from src.memory import WorkingMemory

logger = logging.getLogger(__name__)

GATE_PASS = "pass"
GATE_FAIL = "fail"
GATE_SKIPPED = "skipped"

# Sanitizer output is verbose; cap what we feed back to the model.
_FEEDBACK_LIMIT = 3000


@dataclass
class PatchResult:
    """Result of a single DRV iteration. Gate fields hold pass/fail/skipped."""

    iteration: int
    agent_name: str
    patch_diff: str
    # (function_name, source) when the agent returned a whole-function
    # replacement instead of a unified diff.
    replacement: Optional[tuple[str, str]] = None
    applied_via: str = ""            # "diff" | "content-match" | "function-replacement"
    applied: str = GATE_SKIPPED
    syntax_ok: str = GATE_SKIPPED
    pov_ok: str = GATE_SKIPPED
    regression_ok: str = GATE_SKIPPED
    post_scan_ok: str = GATE_SKIPPED
    fully_validated: bool = False
    error_feedback: str = ""
    analysis: str = ""
    patch_line_count: int = 0        # added + removed lines, excluding headers
    failure_stage: str = ""          # apply | build | pov | regression | post_scan | generation
    critic_verdict: str = ""         # Agent Delta's diagnosis, when it was consulted

    @property
    def executed_gates(self) -> list[str]:
        """Gates that actually ran (i.e. were not skipped) in this iteration."""
        return [
            name for name, state in (
                ("build", self.syntax_ok), ("pov", self.pov_ok),
                ("regression", self.regression_ok), ("post_scan", self.post_scan_ok),
            ) if state != GATE_SKIPPED
        ]


@dataclass
class DRVReport:
    """Complete report from a DRV loop run."""

    agent_name: str
    vulnerability_id: str
    total_iterations: int
    max_iterations: int
    success: bool
    winning_patch: Optional[str] = None
    iterations: list[PatchResult] = field(default_factory=list)
    escalations: list[str] = field(default_factory=list)
    critic_invocations: int = 0
    attempt_ledger: list = field(default_factory=list)

    @property
    def winning_iteration(self) -> Optional[PatchResult]:
        for it in self.iterations:
            if it.fully_validated:
                return it
        return None

    @property
    def last_failure(self) -> str:
        """Feedback from the final failing iteration — the real failure reason."""
        for it in reversed(self.iterations):
            if it.error_feedback:
                return it.error_feedback
        return ""

    @property
    def last_failure_stage(self) -> str:
        for it in reversed(self.iterations):
            if it.failure_stage:
                return it.failure_stage
        return ""

    def summary(self) -> str:
        status = "✅ PATCHED" if self.success else "❌ UNRESOLVED"
        return (
            f"[{self.agent_name}] {status} | "
            f"vuln={self.vulnerability_id} | "
            f"iterations={self.total_iterations}/{self.max_iterations}"
        )


class DRVLoop:
    """
    Detect-Repair-Verify loop.

    Per iteration:
      1. Agent generates a patch diff.
      2. A fresh workspace is created from the target's sources.
      3. The patch is applied to the workspace (apply gate).
      4. The workspace is compiled with sanitizers (build gate).
      5. The PoV input is replayed against the patched binary (pov gate).
      6. A benign input is replayed against the patched binary (regression gate).
      7. Semgrep re-scans the patched file for newly introduced findings.
    Any failure is fed back verbatim to the agent for the next attempt.
    """

    def __init__(self, llm_client, context_extractor=None, semgrep_runner=None,
                 use_critic: bool = True):
        self.llm_client = llm_client
        self.context_extractor = context_extractor
        self.semgrep_runner = semgrep_runner
        # Agent Delta reviews rejected patches; the policy decides when it is
        # worth the call. Both are inert until a gate actually fails.
        self.critic = Critic(llm_client) if use_critic else None

    # -- public API ---------------------------------------------------------

    def run(
        self,
        agent_name: str,
        vulnerability_context: str,
        target_file: str,
        max_iterations: int = 5,
        vulnerability_id: str = "unknown",
        build_command: Optional[str] = None,
        test_command: Optional[str] = None,
        pov_command: Optional[str] = None,
        source_dir: Optional[str] = None,
    ) -> DRVReport:
        """
        Run the full DRV loop for one agent on one vulnerability.

        build/pov/test commands are templates expanded with {src}, {srcdir},
        {bin}, {workspace}. A command left as None means that gate is SKIPPED
        and is reported as such — it is never counted as a pass.
        """
        report = DRVReport(
            agent_name=agent_name,
            vulnerability_id=vulnerability_id,
            total_iterations=0,
            max_iterations=max_iterations,
            success=False,
        )

        feedback = None
        policy = EscalationPolicy()
        # Working memory: what this agent has already tried on this bug. Without
        # it each iteration sees only the latest rejection, which is how agents
        # end up oscillating between two already-refused fixes.
        working = WorkingMemory(vulnerability_id)

        for iteration in range(1, max_iterations + 1):
            logger.info(f"[{agent_name}] DRV iteration {iteration}/{max_iterations}")

            # Deterministic escalation: once an agent has proved it cannot emit a
            # byte-exact diff, stop asking for one.
            if policy.should_force_replacement():
                feedback = (
                    (feedback or "")
                    + "\n\nMANDATORY FORMAT CHANGE: your diffs keep failing to apply. "
                    "Do NOT output a diff this time. Output the COMPLETE corrected "
                    "function in a ```c block whose first line is "
                    "`// FUNCTION: <exact_function_name>`."
                )

            ledger = working.render()
            iteration_feedback = f"{feedback}\n\n{ledger}" if (feedback and ledger) else (feedback or ledger or None)

            llm_result = self.llm_client.generate_patch(
                agent_name=agent_name,
                vulnerability_context=vulnerability_context,
                feedback=iteration_feedback,
                iteration=iteration,
            )
            patch_diff = llm_result["patch"]
            replacement = llm_result.get("replacement")

            result = PatchResult(
                iteration=iteration,
                agent_name=agent_name,
                patch_diff=patch_diff or "",
                replacement=replacement,
                analysis=llm_result.get("analysis", ""),
                patch_line_count=self.count_patch_lines(patch_diff or ""),
            )
            report.iterations.append(result)
            report.total_iterations = iteration

            if not patch_diff and not replacement:
                result.failure_stage = "generation"
                result.error_feedback = (
                    "ERROR: No patch was found in your response. Return EITHER a "
                    "whole corrected function in a ```c block starting with "
                    "`// FUNCTION: <name>`, OR a unified diff in a ```diff block."
                )
                policy.record_failure("generation", gist="(no patch produced)")
                feedback = result.error_feedback
                continue

            if self._verify(result, target_file, patch_diff,
                            build_command, pov_command, test_command, source_dir):
                report.success = True
                # Record whatever actually got applied, so the audit trail shows
                # the real change rather than an unused diff.
                if result.applied_via == "function-replacement" and result.replacement:
                    name, source = result.replacement
                    report.winning_patch = f"// FUNCTION: {name}\n{source}"
                else:
                    report.winning_patch = patch_diff
                logger.info(f"[{agent_name}] ✅ Patch validated at iteration {iteration}")
                break

            # --- the patch was rejected: diagnose before trying again ---
            attempted = result.patch_diff or (
                result.replacement[1] if result.replacement else ""
            )
            # The policy needs the gist, not just the stage: four different
            # attempts that each fail the PoV gate are progress, four identical
            # ones are a loop, and only the latter is worth giving up on.
            policy.record_failure(
                result.failure_stage or "unknown",
                gist=working.summarise_patch(attempted),
            )
            working.record(
                iteration=iteration, agent=agent_name,
                patch=attempted,
                rejected_by=result.failure_stage or "unknown",
            )
            feedback = result.error_feedback

            if self.critic and policy.should_invoke_critic(result.failure_stage):
                verdict = self.critic.review(
                    vulnerability_context=vulnerability_context,
                    patch=result.patch_diff or str(result.replacement),
                    gate_output=result.error_feedback,
                    failure_stage=result.failure_stage,
                )
                if verdict:
                    result.critic_verdict = verdict.verdict
                    if working.attempts:
                        working.attempts[-1].critic_verdict = verdict.verdict
                    feedback = f"{result.error_feedback}\n\n{verdict.as_guidance()}"
                    logger.info(
                        f"[{agent_name}] critic: {verdict.verdict} — {verdict.instruction[:90]}"
                    )

            if policy.should_stop_early() and iteration < max_iterations:
                policy.note(f"stopped early at iteration {iteration}: no progress")
                logger.info(
                    f"[{agent_name}] stopping early — '{result.failure_stage}' failed "
                    f"{policy.stage_counts.get(result.failure_stage)}x with no progress"
                )
                break

        report.attempt_ledger = working.attempts
        report.escalations = policy.escalations
        report.critic_invocations = self.critic.invocations if self.critic else 0

        if not report.success:
            logger.warning(
                f"[{agent_name}] ❌ Failed after {report.total_iterations} iterations "
                f"for {vulnerability_id} (last stage: {report.last_failure_stage})"
            )
        return report

    # -- verification -------------------------------------------------------

    def _verify(
        self, result: PatchResult, target_file: str, patch_diff: str,
        build_command: Optional[str], pov_command: Optional[str],
        test_command: Optional[str], source_dir: Optional[str],
    ) -> bool:
        """Run every configured gate against the patched workspace."""
        with tempfile.TemporaryDirectory(prefix="kavach_drv_") as tmpdir:
            workspace = Path(tmpdir)
            try:
                patched_src = self._materialise(workspace, target_file, source_dir)
            except FileNotFoundError as e:
                result.failure_stage = "apply"
                result.applied = GATE_FAIL
                result.error_feedback = str(e)
                return False

            # Gate 1 — patch application.
            # A whole-function replacement is spliced by AST range and cannot
            # fail on formatting, so it is preferred when the agent supplied one.
            original_text = patched_src.read_text()
            ok, detail = False, ""
            if result.replacement:
                name, source = result.replacement
                ok, detail = self._apply_replacement(patched_src, name, source)
                if ok:
                    result.applied_via = "function-replacement"

            if not ok and patch_diff:
                diff_ok, diff_detail = self._apply_patch(workspace, patched_src, patch_diff)
                if diff_ok:
                    ok = True
                    result.applied_via = "diff"
                else:
                    detail = (detail + "\n" + diff_detail).strip()

            if ok:
                # Measure the actual change. Counting +/- markers only works for
                # unified diffs; a whole-function replacement has none, which
                # silently reported every such patch as "0 lines changed".
                result.patch_line_count = self._changed_lines(
                    original_text, patched_src.read_text()
                )

            result.applied = GATE_PASS if ok else GATE_FAIL
            if not ok:
                result.failure_stage = "apply"
                result.error_feedback = (
                    "PATCH FAILED TO APPLY.\n\n" + detail + "\n\n"
                    "Easiest fix: return the COMPLETE corrected function instead of a "
                    "diff, in a ```c block whose first line is "
                    "`// FUNCTION: <exact_function_name>`. That form is spliced in by "
                    "name and cannot fail on context mismatch."
                )
                return False

            binary = workspace / "kavach_target"
            ctx = {
                "src": str(patched_src),
                "srcdir": str(patched_src.parent),
                "bin": str(binary),
                "workspace": str(workspace),
            }

            # Gate 2 — build
            if build_command:
                ok, detail = self._run(self.expand(build_command, ctx), "Build", cwd=workspace)
                result.syntax_ok = GATE_PASS if ok else GATE_FAIL
                if not ok:
                    result.failure_stage = "build"
                    result.error_feedback = f"BUILD FAILED:\n{detail}"
                    return False

            # Gate 3 — proof of vulnerability replayed on the patched binary
            if pov_command:
                ok, detail = self._run(self.expand(pov_command, ctx), "PoV", cwd=workspace)
                result.pov_ok = GATE_PASS if ok else GATE_FAIL
                if not ok:
                    result.failure_stage = "pov"
                    result.error_feedback = (
                        "PROOF-OF-VULNERABILITY STILL REPRODUCES. The patched binary "
                        "still crashes (or is still exploitable) on the attack input. "
                        "Your fix does not address the root cause.\n\n" + detail
                    )
                    return False

            # Gate 4 — regression on benign input
            if test_command:
                ok, detail = self._run(self.expand(test_command, ctx), "Regression", cwd=workspace)
                result.regression_ok = GATE_PASS if ok else GATE_FAIL
                if not ok:
                    result.failure_stage = "regression"
                    result.error_feedback = (
                        "REGRESSION TEST FAILED. Your patch broke valid, non-malicious "
                        "behaviour. Fix the vulnerability without changing what the "
                        "program does for legitimate input.\n\n" + detail
                    )
                    return False

            # Gate 5 — post-patch static re-scan of the patched file
            if self.semgrep_runner:
                ok, detail = self._post_patch_scan(target_file, patched_src)
                result.post_scan_ok = GATE_PASS if ok else GATE_FAIL
                if not ok:
                    result.failure_stage = "post_scan"
                    result.error_feedback = (
                        "POST-PATCH SCAN: your patch introduces a NEW static finding. "
                        "Fix the original bug without introducing new issues.\n\n" + detail
                    )
                    return False

        result.fully_validated = True
        return True

    @staticmethod
    def _materialise(workspace: Path, target_file: str, source_dir: Optional[str]) -> Path:
        """
        Copy the target's sources into the workspace, preserving the relative
        path layout so that `patch -p1` resolves `a/<path>` headers naturally.
        Returns the path of the file to be patched inside the workspace.
        """
        target = Path(target_file)
        if not target.exists():
            raise FileNotFoundError(f"Target file not found: {target_file}")

        rel = Path(target_file)
        if rel.is_absolute():
            rel = Path(target.name)

        if source_dir:
            src_root = Path(source_dir)
            if not src_root.exists():
                raise FileNotFoundError(f"Source dir not found: {source_dir}")
            dest_root = workspace / src_root
            dest_root.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src_root, dest_root, dirs_exist_ok=True)
            return workspace / rel

        dest = workspace / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, dest)
        return dest

    @staticmethod
    def _apply_patch(workspace: Path, patched_src: Path, patch_diff: str) -> tuple[bool, str]:
        """
        Apply the unified diff inside the workspace. Tries the standard -p1
        layout first, then falls back to naming the target file explicitly at
        several strip levels, which tolerates the path prefixes LLMs invent.
        """
        patch_file = workspace / "kavach.patch"
        patch_file.write_text(patch_diff if patch_diff.endswith("\n") else patch_diff + "\n")

        # Exact-context application is tried first at both strip levels. Only
        # if every exact attempt fails do we allow patch(1) to fuzz the hunk
        # location (-F 3): LLM diffs routinely carry correct edits with drifted
        # line numbers. Fuzzed results still face the build/PoV/regression
        # gates, so a mislocated hunk cannot pass unnoticed.
        exact = [
            ["patch", "-p1", "-l", "-f", "-i", str(patch_file)],
            ["patch", "-p0", "-l", "-f", "-i", str(patch_file)],
            ["patch", "-p1", "-l", "-f", str(patched_src), "-i", str(patch_file)],
            ["patch", "-p0", "-l", "-f", str(patched_src), "-i", str(patch_file)],
        ]
        fuzzy = [cmd[:1] + ["-F", "3"] + cmd[1:] for cmd in exact]
        attempts = exact + fuzzy

        errors = []
        original = patched_src.read_text()
        for cmd in attempts:
            dry = subprocess.run(
                cmd + ["--dry-run"], cwd=workspace,
                capture_output=True, text=True, timeout=60,
            )
            if dry.returncode != 0:
                errors.append(f"$ {' '.join(cmd[:3])} --dry-run\n{dry.stdout}{dry.stderr}")
                continue

            applied = subprocess.run(
                cmd, cwd=workspace, capture_output=True, text=True, timeout=60,
            )
            if applied.returncode == 0:
                if patched_src.read_text() == original:
                    errors.append("patch reported success but the file is unchanged")
                    continue
                return True, applied.stdout
            errors.append(f"$ {' '.join(cmd[:3])}\n{applied.stdout}{applied.stderr}")

        # Final tier: locate each hunk by its CONTENT instead of its line
        # numbers. LLM diffs frequently carry a correct edit under an invented
        # @@ header, and BSD patch(1) refuses to search past EOF. The edit is
        # only accepted when its context matches uniquely, and the result still
        # has to clear every downstream gate.
        ok, detail = DRVLoop._apply_by_content(patched_src, patch_diff)
        if ok:
            return True, "applied by content-matching fallback"
        errors.append(f"$ content-match fallback\n{detail}")

        return False, "\n".join(errors)[:_FEEDBACK_LIMIT]

    def _apply_replacement(
        self, target: Path, function_name: str, new_source: str
    ) -> tuple[bool, str]:
        """
        Splice a whole corrected function into the file by AST range.

        Needs the Tree-sitter extractor; if none was supplied the caller falls
        back to diff application.
        """
        if not self.context_extractor:
            return False, "function replacement unavailable: no context extractor configured"

        language = "cpp" if target.suffix in (".cc", ".cpp", ".cxx", ".hpp") else "c"
        try:
            ok = self.context_extractor.replace_function(
                str(target), function_name, new_source, language=language
            )
        except Exception as e:
            return False, f"function replacement failed: {type(e).__name__}: {e}"

        if not ok:
            return False, (
                f"function '{function_name}' was not found in {target.name}. "
                "Use the exact name as it appears in the source."
            )
        return True, ""

    @staticmethod
    def _parse_hunks(patch_diff: str) -> list[list[str]]:
        """Split a unified diff into hunks (list of raw body lines)."""
        hunks, current = [], None
        for line in patch_diff.splitlines():
            if line.startswith("@@"):
                if current:
                    hunks.append(current)
                current = []
                continue
            if current is None:
                continue          # still in the ---/+++ header
            if line.startswith(("--- ", "+++ ")):
                continue
            current.append(line)
        if current:
            hunks.append(current)
        return [h for h in hunks if h]

    @staticmethod
    def _apply_by_content(target: Path, patch_diff: str) -> tuple[bool, str]:
        """
        Apply each hunk by finding its context+removed lines verbatim in the
        file. Refuses ambiguous matches so a hunk can never land in the wrong
        place silently.
        """
        hunks = DRVLoop._parse_hunks(patch_diff)
        if not hunks:
            return False, "no hunks found in diff"

        lines = target.read_text().splitlines()

        for index, hunk in enumerate(hunks, 1):
            search = [l[1:] for l in hunk if l.startswith((" ", "-")) or l == ""]
            replace = [l[1:] for l in hunk if l.startswith((" ", "+")) or l == ""]
            if not search:
                return False, f"hunk {index}: nothing to match against"

            def norm(seq):
                return [s.strip() for s in seq]

            needle = norm(search)
            matches = [
                i for i in range(len(lines) - len(needle) + 1)
                if norm(lines[i:i + len(needle)]) == needle
            ]
            if len(matches) != 1:
                return False, (
                    f"hunk {index}: context matched {len(matches)} locations "
                    f"(need exactly 1)"
                )

            at = matches[0]
            lines[at:at + len(needle)] = replace

        target.write_text("\n".join(lines) + "\n")
        return True, ""

    @staticmethod
    def expand(command: str, ctx: dict) -> str:
        """
        Expand {src}/{srcdir}/{bin}/{workspace} in a command template.

        Only these four names are substituted, by literal replacement. Anything
        else in braces — shell brace expansion, awk programs, ${arr[1]} — is
        left exactly as written. (str.format cannot be used here: it mangles
        constructs like ${x[1]} into $x.)
        """
        out = command
        for key in ("src", "srcdir", "bin", "workspace"):
            if key in ctx:
                out = out.replace("{" + key + "}", str(ctx[key]))
        return out

    @staticmethod
    def _run(command: str, label: str, cwd: Optional[Path] = None) -> tuple[bool, str]:
        """Run a shell command; return (exit==0, captured output)."""
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=180, cwd=str(cwd) if cwd else None,
                env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0", MallocNanoZone="0"),
            )
        except subprocess.TimeoutExpired:
            return False, f"{label} timed out after 180 seconds"
        except Exception as e:  # pragma: no cover - defensive
            return False, f"{label} error: {e}"

        if proc.returncode == 0:
            return True, proc.stdout[:_FEEDBACK_LIMIT]

        return False, (
            f"{label} failed (exit code {proc.returncode})\n"
            f"--- stdout ---\n{DRVLoop._salient(proc.stdout, _FEEDBACK_LIMIT // 3)}\n"
            f"--- stderr ---\n{DRVLoop._salient(proc.stderr, 2 * _FEEDBACK_LIMIT // 3)}"
        )

    @staticmethod
    def _salient(output: str, limit: int) -> str:
        """
        Trim tool output while keeping the lines that explain the failure.

        Naive truncation is actively harmful here: an AddressSanitizer report
        opens with a shadow-memory banner and closes with the SUMMARY line and
        the allocation stack — exactly the parts a repair agent needs. Cutting
        the first N characters keeps the banner and discards the diagnosis.

        This keeps the error line, the frames naming the target's own source,
        and the SUMMARY, then fills any remaining budget with the head of the
        output.
        """
        if len(output) <= limit:
            return output

        lines = output.splitlines()
        priority, seen = [], set()

        def take(line: str) -> None:
            key = line.strip()
            if key and key not in seen:
                seen.add(key)
                priority.append(line)

        for line in lines:
            stripped = line.strip()
            if (
                "ERROR:" in stripped
                or stripped.startswith("SUMMARY:")
                or "runtime error:" in stripped
                or "error:" in stripped                      # compiler diagnostics
                or "REGRESSION:" in stripped
                or (stripped.startswith("#") and ".c:" in stripped)   # source frames
                or "is located" in stripped                  # ASan locates the overflow
                or "allocated by" in stripped
            ):
                take(line)

        kept = "\n".join(priority)[:limit]
        remaining = limit - len(kept)
        if remaining > 200:
            head = "\n".join(lines)[: remaining - 40]
            return f"{kept}\n--- (context) ---\n{head}"
        return kept

    def _post_patch_scan(self, original_file: str, patched_file: Path) -> tuple[bool, str]:
        """
        Re-scan the ACTUAL patched file and fail if it carries findings the
        original did not have.
        """
        try:
            original_rules = {f.rule_id for f in self.semgrep_runner.scan_file(original_file)}
            patched_findings = self.semgrep_runner.scan_file(str(patched_file))
            new = [f for f in patched_findings if f.rule_id not in original_rules]
            if new:
                detail = "\n".join(
                    f"- {f.rule_id} at line {f.start_line}: {f.message}" for f in new[:5]
                )
                logger.warning(f"Post-patch scan found {len(new)} new finding(s)")
                return False, detail
            return True, ""
        except Exception as e:
            # A scanner malfunction must not be reported as a security verdict.
            logger.error(f"Post-patch scan error (gate not enforced): {e}")
            return True, ""

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _changed_lines(before: str, after: str) -> int:
        """Lines that actually differ between the original and patched file."""
        diff = difflib.unified_diff(
            before.splitlines(), after.splitlines(), lineterm="", n=0
        )
        return sum(
            1 for line in diff
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        )

    @staticmethod
    def count_patch_lines(patch_diff: str) -> int:
        """Number of real added/removed lines in a unified diff (excludes headers)."""
        count = 0
        for line in patch_diff.splitlines():
            if line.startswith(("+++", "---", "@@")):
                continue
            if line.startswith(("+", "-")):
                count += 1
        return count
