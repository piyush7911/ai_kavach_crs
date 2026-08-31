"""
AI Kavach CRS — LLM Client
Provides a unified interface to OpenAI GPT models for all agents.
Designed to be swappable to local vLLM by changing base_url only.
"""

import re
import time
import logging
import threading
from typing import Optional

from openai import OpenAI, APIError, RateLimitError, APIConnectionError

from config import get_llm_config, AGENT_PROMPTS

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Unified LLM client for all AI Kavach agents.
    Wraps OpenAI API with retry logic, token budgeting, and agent-aware prompting.
    """

    def __init__(self):
        config = get_llm_config()
        self.client = OpenAI(
            api_key=config["api_key"],
            base_url=config["base_url"],
        )
        self.models = config["models"]
        self.max_tokens = config["max_tokens"]
        self.temperature = config["temperature"]
        self.seed = config.get("seed")
        # Backend build identifiers seen this run. If more than one appears, the
        # results came from different server-side builds and are not comparable.
        self.fingerprints: set[str] = set()

        # Token usage tracking. Agents run concurrently, so every mutation of
        # these counters is serialised — otherwise parallel mode silently
        # loses token counts and under-reports cost.
        self._usage_lock = threading.Lock()
        self.usage_log: list[dict] = []
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def generate_patch(
        self,
        agent_name: str,
        vulnerability_context: str,
        feedback: Optional[str] = None,
        iteration: int = 1,
    ) -> dict:
        """
        Generate a patch for a vulnerability using the specified agent.

        Args:
            agent_name: "alpha", "beta", or "gamma"
            vulnerability_context: The vulnerability description, code, crash trace, etc.
            feedback: Optional feedback from a previous DRV iteration (stderr, ASan trace, test output).
            iteration: Current DRV iteration number.

        Returns:
            dict with keys: "analysis" (str), "patch" (str), "raw_response" (str),
                           "model" (str), "tokens_in" (int), "tokens_out" (int)
        """
        if agent_name not in AGENT_PROMPTS:
            raise ValueError(f"Unknown agent: {agent_name}. Must be 'alpha', 'beta', or 'gamma'.")

        prompt_config = AGENT_PROMPTS[agent_name]
        model = self.models[agent_name]
        max_tokens = self.max_tokens[agent_name]

        # Build messages
        messages = [
            {"role": "system", "content": prompt_config["system"]},
            {"role": "user", "content": vulnerability_context},
        ]

        # If we have feedback from a previous DRV iteration, add it
        if feedback and iteration > 1:
            messages.append({
                "role": "user",
                "content": (
                    f"--- DRV Iteration {iteration} ---\n"
                    f"Your previous patch FAILED. Here is the feedback:\n\n"
                    f"{feedback}\n\n"
                    f"Please analyze what went wrong and generate a corrected patch."
                ),
            })

        # Call OpenAI with retry logic
        response = self._call_with_retry(model, messages, max_tokens)

        # Parse response
        raw = response.choices[0].message.content or ""
        patch = self._extract_diff(raw)
        replacement = self._extract_replacement(raw)
        analysis = self._extract_analysis(raw, agent_name)

        # Track usage
        usage = {
            "agent": agent_name,
            "model": model,
            "iteration": iteration,
            "input_tokens": response.usage.prompt_tokens if response.usage else 0,
            "output_tokens": response.usage.completion_tokens if response.usage else 0,
            "timestamp": time.time(),
        }
        with self._usage_lock:
            self.usage_log.append(usage)
            self.total_input_tokens += usage["input_tokens"]
            self.total_output_tokens += usage["output_tokens"]

        logger.info(
            f"[{prompt_config['name']}] iter={iteration} "
            f"tokens_in={usage['input_tokens']} tokens_out={usage['output_tokens']} "
            f"patch_lines={len(patch.splitlines()) if patch else 0}"
        )

        return {
            "analysis": analysis,
            "patch": patch,
            "replacement": replacement,   # (function_name, full_source) or None
            "raw_response": raw,
            "model": model,
            "tokens_in": usage["input_tokens"],
            "tokens_out": usage["output_tokens"],
        }

    def structured_call(
        self,
        model: str,
        system_prompt: str,
        user_content: str,
        schema: dict,
        max_tokens: int = 800,
    ) -> str:
        """
        Call the model with a strict JSON schema and return the raw JSON string.

        Used by the Critic so its verdict is machine-checkable rather than prose
        the repair agent has to interpret. Token usage is recorded exactly as for
        patch calls, so critic cost shows up in the benchmark's totals.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        response = self.client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.0,          # diagnosis should be reproducible
            response_format={"type": "json_schema", "json_schema": schema},
        )

        usage = {
            "agent": "critic",
            "model": model,
            "iteration": 0,
            "input_tokens": response.usage.prompt_tokens if response.usage else 0,
            "output_tokens": response.usage.completion_tokens if response.usage else 0,
            "timestamp": time.time(),
        }
        with self._usage_lock:
            self.usage_log.append(usage)
            self.total_input_tokens += usage["input_tokens"]
            self.total_output_tokens += usage["output_tokens"]

        return response.choices[0].message.content or ""

    def _call_with_retry(self, model: str, messages: list, max_tokens: int, max_retries: int = 3):
        """Call OpenAI API with exponential backoff retry."""
        for attempt in range(max_retries):
            try:
                kwargs = dict(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=self.temperature,
                )
                if self.seed is not None:
                    kwargs["seed"] = self.seed
                response = self.client.chat.completions.create(**kwargs)
                fp = getattr(response, "system_fingerprint", None)
                if fp:
                    self.fingerprints.add(fp)
                return response
            except RateLimitError as e:
                wait = 2 ** attempt * 5  # 5s, 10s, 20s
                logger.warning(f"Rate limited. Retrying in {wait}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
            except APIConnectionError as e:
                wait = 2 ** attempt * 2  # 2s, 4s, 8s
                logger.warning(f"Connection error. Retrying in {wait}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
            except APIError as e:
                logger.error(f"OpenAI API error: {e}")
                raise

        raise RuntimeError(f"Failed after {max_retries} retries")

    @staticmethod
    def _extract_diff(response: str) -> str:
        """Extract unified diff from LLM response."""
        # Try to find ```diff ... ``` blocks
        diff_pattern = r"```diff\s*\n(.*?)```"
        matches = re.findall(diff_pattern, response, re.DOTALL)
        if matches:
            return matches[0].strip()

        # Fallback: look for lines starting with --- or +++
        lines = response.split("\n")
        diff_lines = []
        in_diff = False
        for line in lines:
            if line.startswith("--- ") or line.startswith("+++ "):
                in_diff = True
            if in_diff:
                diff_lines.append(line)
                if line.strip() == "" and len(diff_lines) > 3:
                    # End of diff block
                    break

        return "\n".join(diff_lines).strip() if diff_lines else ""

    @staticmethod
    def _extract_replacement(response: str) -> Optional[tuple[str, str]]:
        """
        Extract a whole-function replacement, if the model chose that format.

        Expected shape:

            ```c
            // FUNCTION: process_data
            void process_data(const char *input) { ... }
            ```

        This exists because unified diffs are fragile: the model must reproduce
        context lines byte-for-byte or the patch is rejected even when the fix
        is correct. Diff-application was the single largest source of rejected
        attempts. A whole function is spliced in by AST range, so formatting
        cannot invalidate a good fix — and the patch still faces every gate.

        Returns (function_name, source) or None.
        """
        blocks = re.findall(r"```(?:c|cpp|c\+\+)?\s*\n(.*?)```", response, re.DOTALL)
        for block in blocks:
            match = re.search(r"//\s*FUNCTION:\s*([A-Za-z_][A-Za-z0-9_]*)", block)
            if not match:
                continue
            name = match.group(1)
            # Drop the marker line; keep the function body verbatim.
            source = re.sub(r"^\s*//\s*FUNCTION:.*$", "", block, count=1, flags=re.MULTILINE)
            source = source.strip()
            # A replacement must actually look like a definition of that function.
            if source and name in source and "{" in source and "}" in source:
                return name, source

        # No marker. Models routinely return the corrected function in a plain
        # ```c block and omit the header, and rejecting those as "no patch was
        # found" wastes the whole iteration budget on a formatting detail —
        # observed as five consecutive `generation` failures from one agent on a
        # target it had otherwise analysed correctly.
        #
        # The function name is inferred from the block's own definition instead.
        # This is not a shortcut past verification: the name still has to resolve
        # against the file's AST in `_apply_replacement`, and a wrong guess fails
        # there rather than silently patching the wrong function. Every gate
        # still runs afterwards.
        for block in blocks:
            name = LLMClient._infer_function_name(block)
            if name:
                return name, block.strip()
        return None

    # A C function definition opening a body: optional qualifiers and return
    # type, the name, a parameter list, then `{`. Deliberately strict — it must
    # not match a call, a declaration ending in `;`, or a control statement.
    _DEFINITION = re.compile(
        r"^[A-Za-z_][\w\s\*\(\),]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{",
        re.MULTILINE,
    )
    _NOT_A_FUNCTION = {"if", "for", "while", "switch", "return", "sizeof", "do"}

    @classmethod
    def _infer_function_name(cls, block: str) -> Optional[str]:
        """
        Name of the single function defined in a code block, or None.

        Returns None when the block defines zero or several functions: with more
        than one there is no way to tell which the model meant to replace, and
        guessing would splice a function into the wrong AST range.
        """
        names = [
            m.group(1) for m in cls._DEFINITION.finditer(block)
            if m.group(1) not in cls._NOT_A_FUNCTION
        ]
        return names[0] if len(names) == 1 else None

    @staticmethod
    def _extract_analysis(response: str, agent_name: str) -> str:
        """Extract analysis text (everything before the diff block)."""
        if agent_name in ("beta", "gamma"):
            # These agents don't provide analysis
            return ""

        # Everything before the first ```diff block
        parts = response.split("```diff")
        if len(parts) > 1:
            return parts[0].strip()
        return response.strip()

    # USD per 1M tokens, (input, output). Keyed by model id prefix.
    PRICING = {
        "gpt-4o-mini": (0.15, 0.60),
        "gpt-4o": (2.50, 10.00),
        "gpt-4.1-mini": (0.40, 1.60),
        "gpt-4.1": (2.00, 8.00),
    }

    def get_usage_summary(self) -> dict:
        """
        Total token usage and estimated cost.

        Cost is only reported for models with a known price. Tokens spent on an
        unpriced model are counted separately instead of being silently billed
        at some other model's rate.
        """
        cost = 0.0
        unpriced_tokens = 0
        unpriced_models = set()

        with self._usage_lock:
            entries = list(self.usage_log)
            total_in, total_out = self.total_input_tokens, self.total_output_tokens

        for entry in entries:
            model = entry["model"]
            price = next(
                (p for prefix, p in sorted(self.PRICING.items(), key=lambda kv: -len(kv[0]))
                 if model.startswith(prefix)),
                None,
            )
            if price is None:
                unpriced_tokens += entry["input_tokens"] + entry["output_tokens"]
                unpriced_models.add(model)
                continue
            cost += (entry["input_tokens"] / 1_000_000) * price[0]
            cost += (entry["output_tokens"] / 1_000_000) * price[1]

        return {
            "total_calls": len(entries),
            "total_input_tokens": total_in,
            "total_output_tokens": total_out,
            "estimated_cost_usd": round(cost, 6),
            "seed": self.seed,
            "temperature": self.temperature,
            "system_fingerprints": sorted(self.fingerprints),
            "unpriced_tokens": unpriced_tokens,
            "unpriced_models": sorted(unpriced_models),
        }
