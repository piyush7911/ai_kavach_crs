"""
AI Kavach CRS — Agent Memory

Implements the memory taxonomy that the agent literature converged on
(working / episodic / semantic / procedural, per the CoALA framing and the 2026
survey "Memory for Autonomous LLM Agents"), specialised for vulnerability repair.

    WorkingMemory     Within one repair loop: the ledger of attempts already
                      made and why each was rejected. Prevents the agent from
                      re-proposing a fix a gate has already refused.

    EpisodicMemory    One record per target: the full trajectory — attempts,
                      rejections, critic verdicts, outcome. Append-only history.

    SemanticMemory    Cross-target, distilled: validated fix patterns keyed by
                      (CWE, crash class). The compounding asset — every solved
                      bug makes the next similar one easier.

    ProceduralMemory  Which agent actually wins for which bug class, and how
                      many iterations it typically needs. Drives routing.

Why this is not the usual agent-memory design
---------------------------------------------
The survey's central unsolved problem is **trustworthy reflection**: agents
store self-assessed lessons that were never checked, and a wrong lesson becomes
permanent ("approach X always fails" → X is never tried again). That failure
mode — self-reinforcing error — is what makes most agent memory risky.

We are in the rare position of having ground truth. A fix is not written to
semantic memory because an agent *believes* it worked; it is written only after
the patch compiled under sanitizers, the proof-of-vulnerability stopped
reproducing, regression passed, and hardening failed to falsify it. Memory here
records *verified outcomes*, not opinions.

Two further guards against the documented failure modes:

  * **Pitfalls are recorded as observations, never as conclusions.** We store
    "a patch of this shape was rejected by the PoV gate", not "this approach
    never works". The agent decides what to infer.
  * **Entries carry provenance and confidence**, and confidence decays when a
    retrieved pattern is followed and still fails — so a stale pattern loses
    influence instead of silently misleading forever.
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_STORE = Path("benchmark_workspace/memory")


# ---------------------------------------------------------------------------
# Working memory — within a single repair loop
# ---------------------------------------------------------------------------

@dataclass
class Attempt:
    """One rejected repair attempt."""

    iteration: int
    agent: str
    summary: str          # a compact description of what was changed
    rejected_by: str      # apply | build | pov | regression | post_scan
    critic_verdict: str = ""


class WorkingMemory:
    """
    The attempt ledger for one vulnerability.

    Observed problem this solves: agents oscillated between two rejected fixes
    for a full iteration budget (`insufficient → regression_risk → insufficient
    → regression_risk`), because each iteration only saw the *latest* failure.
    The ledger shows every prior attempt at once.
    """

    MAX_RENDERED = 6

    def __init__(self, vulnerability_id: str):
        self.vulnerability_id = vulnerability_id
        self.attempts: list[Attempt] = []

    def record(self, iteration: int, agent: str, patch: str, rejected_by: str,
               critic_verdict: str = "") -> None:
        self.attempts.append(Attempt(
            iteration=iteration, agent=agent,
            summary=self.summarise_patch(patch),
            rejected_by=rejected_by, critic_verdict=critic_verdict,
        ))

    @staticmethod
    def summarise_patch(patch: str) -> str:
        """
        One-line gist of a patch, used both to show the agent what it has
        already tried and to decide whether two attempts are the same.

        Two formats reach this function and they need different handling. A
        unified diff is characterised by the lines it ADDS. A whole-function
        replacement — which the escalation policy *forces* after repeated apply
        failures — has no `+` lines at all, so the old diff-only logic fell back
        to "first three non-empty lines". For a replacement those are the
        signature and the opening brace: identical for every attempt at the same
        function. Every distinct attempt therefore collapsed to one gist, which
        made the ledger useless ("do not repeat these" listing the same entry
        repeatedly) and made `has_tried` report false positives.

        A digest over the whole normalised body is appended so that two attempts
        can never be judged identical unless they really are, however long they
        are or however much they share a prefix.
        """
        if not patch:
            return "(no patch produced)"

        lines = patch.splitlines()
        is_diff = any(
            line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
            for line in lines
        )

        if is_diff:
            body = [
                line[1:].strip() for line in lines
                if line.startswith("+") and not line.startswith("+++")
            ]
            salient = body
        else:
            body = [
                l.strip() for l in lines
                if l.strip() and not l.strip().startswith(("//", "/*", "*", "*/"))
            ]
            # For a replacement, the interesting part is the control flow and the
            # bounds tests — that is where a memory-safety fix lives. The
            # signature and bare braces are shared by every attempt.
            salient = [
                l for l in body
                if any(tok in l for tok in (
                    "if", "while", "for", "return",
                    "<", ">", "==", "!=", "&&", "||",
                ))
            ] or body

        body = [b for b in body if b]
        if not body:
            return "(no effective change)"

        digest = hashlib.sha1(" ".join(body).encode("utf-8", "replace")).hexdigest()[:8]
        gist = "; ".join(s for s in salient if s)[:180]
        return f"{gist or '(no effective change)'} [{digest}]"

    def render(self) -> str:
        """Render the ledger for injection into the next prompt."""
        if not self.attempts:
            return ""
        lines = ["--- ATTEMPTS ALREADY REJECTED (do not repeat these) ---"]
        for a in self.attempts[-self.MAX_RENDERED:]:
            verdict = f" [critic: {a.critic_verdict}]" if a.critic_verdict else ""
            lines.append(
                f"  #{a.iteration} ({a.agent}) rejected by {a.rejected_by}{verdict}: {a.summary}"
            )
        lines.append(
            "Your next patch must be materially different from every attempt above."
        )
        return "\n".join(lines)

    def has_tried(self, patch: str) -> bool:
        """True if a materially identical patch was already rejected."""
        gist = self.summarise_patch(patch)
        return any(a.summary == gist for a in self.attempts)


# ---------------------------------------------------------------------------
# Semantic memory — validated, cross-target fix patterns
# ---------------------------------------------------------------------------

@dataclass
class FixPattern:
    """A repair strategy that provably worked, with the traps seen along the way."""

    cwe: str
    crash_class: str
    root_cause: str
    fix_strategy: str                       # what the winning patch did
    pitfalls: list[str] = field(default_factory=list)
    winning_agent: str = ""
    iterations_needed: int = 0
    hardened: bool = False                  # survived re-fuzz + differential
    source_target: str = ""
    created_at: float = 0.0
    times_retrieved: int = 0
    times_helped: int = 0                   # retrieved and the repair then succeeded
    times_misled: int = 0                   # retrieved and the repair still failed

    @property
    def confidence(self) -> float:
        """
        Confidence decays when a pattern is followed and the repair still fails.

        This is the guard against stale or over-general patterns: influence is
        earned by outcomes, not asserted at write time.
        """
        base = 0.9 if self.hardened else 0.6
        used = self.times_helped + self.times_misled
        if used == 0:
            return base
        success_rate = self.times_helped / used
        return round(0.5 * base + 0.5 * success_rate, 3)

    def render(self) -> str:
        lines = [
            f"- Pattern from {self.source_target} ({self.cwe}, {self.crash_class}), "
            f"confidence {self.confidence:.2f}{' [hardened]' if self.hardened else ''}",
            f"    root cause: {self.root_cause}",
            f"    what worked: {self.fix_strategy}",
        ]
        for p in self.pitfalls[:3]:
            lines.append(f"    pitfall observed: {p}")
        return "\n".join(lines)


class SemanticMemory:
    """
    Retrieval over validated fix patterns.

    Retrieval is deliberately **structured, not embedding-based**. The survey
    notes that similarity search answers "what looks like this?" rather than
    "what caused this?", and for our domain the causal key is explicit: the CWE
    and the sanitizer's crash class. Matching on those, then breaking ties on
    root-cause token overlap, is more faithful than cosine distance over prose —
    and it needs no extra model call, so retrieval is free and deterministic.
    """

    def __init__(self, store_dir: Path = DEFAULT_STORE):
        self.path = Path(store_dir) / "semantic.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.patterns: list[FixPattern] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            self.patterns = [FixPattern(**d) for d in json.loads(self.path.read_text())]
        except Exception as e:
            logger.warning(f"Could not load semantic memory ({e}); starting empty")
            self.patterns = []

    def save(self) -> None:
        self.path.write_text(json.dumps([asdict(p) for p in self.patterns], indent=2))

    # -- write path --------------------------------------------------------

    def remember(self, pattern: FixPattern) -> bool:
        """
        Store a validated pattern.

        The write path filters, canonicalises and deduplicates — storing every
        outcome verbatim is the documented way to poison a memory store.
        Returns True if it was stored.
        """
        if not pattern.fix_strategy.strip():
            return False
        pattern.created_at = pattern.created_at or time.time()

        # Deduplicate: same bug class + equivalent strategy.
        for existing in self.patterns:
            if (existing.cwe == pattern.cwe
                    and existing.crash_class == pattern.crash_class
                    and self._similar(existing.fix_strategy, pattern.fix_strategy)):
                # Keep the stronger evidence, merge the pitfalls.
                if pattern.hardened and not existing.hardened:
                    existing.hardened = True
                    existing.fix_strategy = pattern.fix_strategy
                for p in pattern.pitfalls:
                    if p not in existing.pitfalls:
                        existing.pitfalls.append(p)
                self.save()
                return False

        self.patterns.append(pattern)
        self.save()
        logger.info(
            f"Semantic memory: learned a {pattern.cwe}/{pattern.crash_class} pattern "
            f"from {pattern.source_target} (now {len(self.patterns)} patterns)"
        )
        return True

    # -- read path ---------------------------------------------------------

    def recall(self, cwe: str, crash_class: str = "", description: str = "",
               limit: int = 2) -> list[FixPattern]:
        """
        Retrieve the most relevant validated patterns.

        Capped at `limit` deliberately: the documented failure mode of large
        retrieved contexts is attentional dilution, where more recalled material
        makes the model attend to each piece less.
        """
        scored = []
        for p in self.patterns:
            score = 0.0
            if p.cwe and p.cwe == cwe:
                score += 3.0
            if crash_class and p.crash_class and crash_class in p.crash_class:
                score += 2.0
            score += self._overlap(description, f"{p.root_cause} {p.fix_strategy}")
            score *= p.confidence
            if score > 0.5:
                scored.append((score, p))

        scored.sort(key=lambda kv: -kv[0])
        chosen = [p for _, p in scored[:limit]]
        for p in chosen:
            p.times_retrieved += 1
        if chosen:
            self.save()
        return chosen

    def render_for_prompt(self, patterns: list[FixPattern]) -> str:
        if not patterns:
            return ""
        body = "\n".join(p.render() for p in patterns)
        return (
            "--- PRIOR VERIFIED FIXES FOR SIMILAR BUGS ---\n"
            f"{body}\n"
            "These patches passed compilation, exploit replay and regression testing "
            "on other targets. Treat them as evidence, not instructions: apply the "
            "reasoning only if it genuinely fits this code.\n"
        )

    def record_outcome(self, patterns: list[FixPattern], succeeded: bool) -> None:
        """Feed the result back so confidence tracks reality."""
        for used in patterns:
            for stored in self.patterns:
                if (stored.source_target == used.source_target
                        and stored.fix_strategy == used.fix_strategy):
                    if succeeded:
                        stored.times_helped += 1
                    else:
                        stored.times_misled += 1
        if patterns:
            self.save()

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _tokens(text: str) -> set:
        return {t for t in re.findall(r"[a-z_]{4,}", (text or "").lower())}

    @classmethod
    def _overlap(cls, a: str, b: str) -> float:
        ta, tb = cls._tokens(a), cls._tokens(b)
        if not ta or not tb:
            return 0.0
        return 2.0 * len(ta & tb) / len(ta | tb)

    @classmethod
    def _similar(cls, a: str, b: str) -> bool:
        return cls._overlap(a, b) > 0.6


# ---------------------------------------------------------------------------
# Episodic + procedural
# ---------------------------------------------------------------------------

class EpisodicMemory:
    """Append-only trajectory log — one JSON line per processed vulnerability."""

    def __init__(self, store_dir: Path = DEFAULT_STORE):
        self.path = Path(store_dir) / "episodes.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, episode: dict) -> None:
        episode.setdefault("recorded_at", time.time())
        with open(self.path, "a") as f:
            f.write(json.dumps(episode, default=str) + "\n")

    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


class ProceduralMemory:
    """
    Which agent actually wins for which bug class, and how hard it was.

    Enables two things the system currently cannot do: order the ensemble by
    demonstrated competence per CWE, and scale the iteration budget to observed
    difficulty rather than a fixed constant.
    """

    def __init__(self, store_dir: Path = DEFAULT_STORE):
        self.path = Path(store_dir) / "procedural.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stats: dict = {}
        if self.path.exists():
            try:
                self.stats = json.loads(self.path.read_text())
            except Exception:
                self.stats = {}

    def record(self, cwe: str, winning_agent: Optional[str], iterations: int,
               succeeded: bool) -> None:
        entry = self.stats.setdefault(cwe or "unknown", {
            "attempts": 0, "successes": 0, "agent_wins": {}, "iterations": [],
        })
        entry["attempts"] += 1
        if succeeded:
            entry["successes"] += 1
            entry["iterations"].append(iterations)
            if winning_agent:
                entry["agent_wins"][winning_agent] = entry["agent_wins"].get(winning_agent, 0) + 1
        self.path.write_text(json.dumps(self.stats, indent=2))

    def preferred_agent_order(self, cwe: str, default: list[str]) -> list[str]:
        """Order agents by demonstrated wins on this CWE; unproven agents keep their order."""
        wins = self.stats.get(cwe, {}).get("agent_wins", {})
        if not wins:
            return default
        return sorted(default, key=lambda a: (-wins.get(a, 0), default.index(a)))

    def suggested_iterations(self, cwe: str, default: int) -> int:
        """
        Budget from observed difficulty: bugs of this class that were solved in
        two iterations do not need eight, and vice versa.
        """
        iters = self.stats.get(cwe, {}).get("iterations", [])
        if len(iters) < 2:
            return default
        typical = sorted(iters)[len(iters) // 2]
        return max(2, min(default, typical + 2))


class MemorySystem:
    """Facade wiring the four memory types together."""

    def __init__(self, store_dir: Path = DEFAULT_STORE, enabled: bool = True):
        self.enabled = enabled
        self.semantic = SemanticMemory(store_dir)
        self.episodic = EpisodicMemory(store_dir)
        self.procedural = ProceduralMemory(store_dir)

    def recall_for(self, cwe: str, crash_class: str, description: str) -> list[FixPattern]:
        if not self.enabled:
            return []
        return self.semantic.recall(cwe, crash_class, description)

    def learn_from(
        self,
        target_id: str,
        cwe: str,
        crash_class: str,
        root_cause: str,
        fix_strategy: str,
        pitfalls: list[str],
        winning_agent: str,
        iterations: int,
        hardened: bool,
    ) -> bool:
        """
        Record a *validated* fix. Called only after the patch cleared every gate.

        Nothing is learned from a failed repair beyond the pitfalls, which are
        stored as observations attached to a successful pattern — never as a
        standalone conclusion that some approach "does not work".
        """
        if not self.enabled:
            return False
        return self.semantic.remember(FixPattern(
            cwe=cwe, crash_class=crash_class, root_cause=root_cause,
            fix_strategy=fix_strategy, pitfalls=pitfalls,
            winning_agent=winning_agent, iterations_needed=iterations,
            hardened=hardened, source_target=target_id,
        ))

    def stats(self) -> dict:
        return {
            "semantic_patterns": len(self.semantic.patterns),
            "hardened_patterns": sum(1 for p in self.semantic.patterns if p.hardened),
            "episodes": len(self.episodic.all()),
            "cwe_classes_seen": len(self.procedural.stats),
        }
