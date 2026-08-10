"""
AI Kavach CRS — Agent Delta, The Critic (LLM-as-Judge).

Adapted from two multi-agent references:

  * Anthropic, *How we built our multi-agent research system* — LLM-as-judge with
    an explicit rubric, and giving every subagent an objective, an output format,
    and clear boundaries.
  * Google ADK codelab, *Building a Multi-Agent System* — a Judge agent returning
    a strict Pydantic schema (`status` + `feedback`), plus a deterministic
    EscalationChecker that decides when the loop changes course.

Why this exists
---------------
Before the Critic, a rejected patch went back to its author with nothing but raw
tool output — a compiler error or an AddressSanitizer dump. Agents responded by
resubmitting near-identical patches until their iteration budget ran out. The
benchmark's `pov` failures were dominated by fixes that removed the *reported*
symptom while leaving the bug reachable by another path.

The Critic sits between the failing gate and the next repair attempt. It reads
the vulnerability, the rejected patch, and the exact gate output, and returns a
structured verdict naming the root cause, what the patch missed, and one concrete
instruction for the next attempt.

It is a judge, not a patcher: it never proposes code. That separation keeps its
output short, cheap, and easy to validate.
"""

import json
import logging
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)


class CriticFeedback(BaseModel):
    """Strict schema for a Critic verdict — the analogue of ADK's JudgeFeedback."""

    verdict: Literal["insufficient", "wrong_target", "malformed", "regression_risk"] = Field(
        description=(
            "Why the attempt failed. "
            "'insufficient' = right location, incomplete fix; "
            "'wrong_target' = patched the wrong line or function; "
            "'malformed' = patch could not be applied or compiled; "
            "'regression_risk' = fixes the bug but breaks valid behaviour."
        )
    )
    root_cause: str = Field(
        description="The actual defect in one sentence, naming the variable or expression."
    )
    what_the_patch_missed: str = Field(
        description=(
            "The specific consequence the previous attempt overlooked — e.g. a "
            "secondary read that still runs out of bounds after the write was fixed."
        )
    )
    instruction: str = Field(
        description=(
            "ONE concrete, actionable instruction for the next attempt. "
            "Name the exact change. No alternatives, no hedging."
        )
    )

    def as_guidance(self) -> str:
        """Render the verdict as feedback for the next repair iteration."""
        return (
            "--- CRITIC REVIEW (Agent Delta) ---\n"
            f"Verdict: {self.verdict}\n"
            f"Root cause: {self.root_cause}\n"
            f"What your patch missed: {self.what_the_patch_missed}\n"
            f"Do this next: {self.instruction}"
        )


# JSON Schema handed to the model so the response is structurally guaranteed.
CRITIC_SCHEMA = {
    "name": "critic_feedback",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["verdict", "root_cause", "what_the_patch_missed", "instruction"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["insufficient", "wrong_target", "malformed", "regression_risk"],
            },
            "root_cause": {"type": "string"},
            "what_the_patch_missed": {"type": "string"},
            "instruction": {"type": "string"},
        },
    },
}

CRITIC_SYSTEM_PROMPT = (
    "You are Agent Delta, the Critic: a strict security reviewer in an automated "
    "patching pipeline.\n\n"
    "A patch was just REJECTED by an automated verification gate. You are given the "
    "vulnerability, the rejected patch, and the verbatim output of the gate that "
    "rejected it. Your job is to diagnose the failure so the next attempt succeeds.\n\n"
    "METHOD:\n"
    "1. Read the gate output first. It is ground truth — it says exactly what still "
    "goes wrong.\n"
    "2. Identify the ROOT CAUSE, not the reported symptom. A sanitizer names the "
    "line that faulted, which is often downstream of the real defect.\n"
    "3. Determine what the patch overlooked. Common cases:\n"
    "   - The write was bounded but a later read still runs off the end.\n"
    "   - A loop bound was corrected but a terminator or sentinel is now missing.\n"
    "   - An arithmetic check was added after the overflow had already happened.\n"
    "   - The allocation was resized but the copy length was not, or vice versa.\n"
    "   - Input was sanitised for one metacharacter but not the others.\n"
    "4. Give ONE concrete instruction naming the exact change to make.\n\n"
    "RULES:\n"
    "- Do NOT write code or a patch. You diagnose; another agent repairs.\n"
    "- Be specific: name variables, sizes, and expressions from the source.\n"
    "- If the gate output shows the patch failed to apply or compile, the verdict is "
    "'malformed' and your instruction must be about the output format, not security.\n"
    "- Never claim the patch is fine. It was rejected; something is wrong."
)


class Critic:
    """Diagnoses rejected patches. Invoked only on repeated failure (see EscalationPolicy)."""

    def __init__(self, llm_client, model: Optional[str] = None):
        self.llm_client = llm_client
        self.model = model or llm_client.models.get("beta")
        self.invocations = 0

    def review(
        self,
        vulnerability_context: str,
        patch: str,
        gate_output: str,
        failure_stage: str,
    ) -> Optional[CriticFeedback]:
        """
        Return a structured verdict, or None if the model produced nothing usable.

        A failed critique is never fatal: the DRV loop falls back to the raw gate
        output, which is what it used before the Critic existed.
        """
        user_content = (
            f"VULNERABILITY UNDER REPAIR:\n{vulnerability_context}\n\n"
            f"REJECTED PATCH:\n```\n{patch[:4000]}\n```\n\n"
            f"GATE THAT REJECTED IT: {failure_stage}\n"
            f"VERBATIM GATE OUTPUT:\n```\n{gate_output[:4000]}\n```\n\n"
            "Diagnose the failure."
        )

        try:
            raw = self.llm_client.structured_call(
                model=self.model,
                system_prompt=CRITIC_SYSTEM_PROMPT,
                user_content=user_content,
                schema=CRITIC_SCHEMA,
                max_tokens=600,
            )
            self.invocations += 1
            return CriticFeedback(**json.loads(raw))
        except (ValidationError, json.JSONDecodeError) as e:
            logger.warning(f"Critic returned unusable output: {e}")
            return None
        except Exception as e:
            logger.warning(f"Critic call failed: {e}")
            return None


class EscalationPolicy:
    """
    Deterministic controller for the repair loop.

    This is the counterpart of the ADK codelab's `EscalationChecker`: plain Python,
    no LLM, deciding when the loop should change course or stop. Keeping it
    deterministic means loop control cannot itself hallucinate.

    Decisions:
      * **Invoke the Critic** once an agent has failed twice, or immediately when a
        proof-of-vulnerability replay fails — a PoV failure means the fix is wrong
        in a way the raw sanitizer dump has already failed to convey.
      * **Force the whole-function format** after two application failures, since
        the agent has demonstrated it cannot produce a byte-exact diff.
      * **Stop early** when the same stage fails repeatedly with no change in
        outcome, rather than burning the remaining budget.
    """

    CRITIC_AFTER_FAILURES = 2
    FORCE_REPLACEMENT_AFTER_APPLY_FAILURES = 2
    GIVE_UP_AFTER_IDENTICAL_FAILURES = 4

    def __init__(self):
        self.stage_counts: dict[str, int] = {}
        self.total_failures = 0
        self.escalations: list[str] = []

    def record_failure(self, stage: str) -> None:
        self.stage_counts[stage] = self.stage_counts.get(stage, 0) + 1
        self.total_failures += 1

    def should_invoke_critic(self, stage: str) -> bool:
        if stage == "pov":
            return True          # a wrong fix always deserves a diagnosis
        return self.total_failures >= self.CRITIC_AFTER_FAILURES

    def should_force_replacement(self) -> bool:
        return (
            self.stage_counts.get("apply", 0) >= self.FORCE_REPLACEMENT_AFTER_APPLY_FAILURES
            or self.stage_counts.get("generation", 0) >= self.FORCE_REPLACEMENT_AFTER_APPLY_FAILURES
        )

    def should_stop_early(self) -> bool:
        """True when one stage keeps failing and nothing is improving."""
        return any(
            count >= self.GIVE_UP_AFTER_IDENTICAL_FAILURES
            for count in self.stage_counts.values()
        )

    def note(self, message: str) -> None:
        self.escalations.append(message)
