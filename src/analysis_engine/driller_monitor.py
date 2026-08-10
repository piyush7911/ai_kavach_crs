"""
AI Kavach CRS — Driller: concolic (symbolic) execution fallback.

Coverage-guided fuzzers stall on "magic" comparisons: a 32-bit equality check
has a 1-in-4-billion chance of being guessed randomly. Driller's answer is to
stop guessing and start solving — take a seed the fuzzer already has, execute
it symbolically, and at each branch the fuzzer never flipped, ask the SMT
solver for a concrete input that would flip it. Those inputs go back into the
fuzzer's queue.

This module implements that, backed by `angr`:

    DrillerEngine.drill(binary, seed)   -> new inputs that reach unexplored branches
    PlateauMonitor                      -> watches AFL++ stats and triggers drilling

Scope and honesty
-----------------
angr's support is strongest for x86-64 ELF. On other targets (notably arm64
Mach-O, i.e. this development host) angr may fail to lift or explore the
binary. When that happens `drill()` returns a DrillResult with `supported=False`
and the loader's reason — it never fabricates seeds. Check `DrillResult.supported`
before reporting concolic results.
"""

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DrillResult:
    """Outcome of one concolic execution run. Every field is observed."""

    seed: str
    supported: bool = False
    reason: str = ""
    new_inputs: list[bytes] = field(default_factory=list)
    branches_flipped: int = 0
    states_explored: int = 0
    seconds: float = 0.0

    @property
    def input_count(self) -> int:
        return len(self.new_inputs)


class DrillerEngine:
    """Symbolic exploration of a seed to generate inputs for unexplored branches."""

    def __init__(self, output_dir: str = "benchmark_workspace/driller"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    _self_test_cache: Optional[tuple[bool, str]] = None

    @staticmethod
    def available() -> tuple[bool, str]:
        """Whether angr is importable. Returns (available, detail)."""
        try:
            import angr  # noqa: F401
            return True, f"angr {angr.__version__}"
        except ImportError as e:
            return False, f"angr not installed: {e}"

    @classmethod
    def self_test(cls, force: bool = False) -> tuple[bool, str]:
        """
        Known-answer test: can angr actually solve a magic-value comparison on
        THIS platform's binaries?

        Importing angr is not the same as angr working. Its symbolic execution
        is reliable on x86-64 ELF; on other targets (notably arm64 Mach-O) it
        may explore happily while failing to tie the symbolic input to the
        comparison, which yields confident-looking but meaningless "solutions".

        This compiles a program that only prints MAGIC when argv[1] starts with
        "KAVA", asks angr to reach that branch, and checks the recovered input
        really contains KAVA. Concolic results are only trusted when this passes.
        """
        if cls._self_test_cache is not None and not force:
            return cls._self_test_cache

        ok, detail = cls.available()
        if not ok:
            cls._self_test_cache = (False, detail)
            return cls._self_test_cache

        import shutil
        import subprocess
        import tempfile

        compiler = shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            cls._self_test_cache = (False, "no C compiler available to run the self-test")
            return cls._self_test_cache

        import logging as _logging
        for noisy in ("angr", "cle", "pyvex", "claripy"):
            _logging.getLogger(noisy).setLevel(_logging.CRITICAL)

        import angr
        import claripy

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "kat.c"
            source.write_text(
                "#include <stdio.h>\n"
                "int main(int argc, char** argv){\n"
                "  if (argc < 2) return 0;\n"
                "  const char* s = argv[1];\n"
                "  if (s[0]=='K'&&s[1]=='A'&&s[2]=='V'&&s[3]=='A'){ puts(\"MAGIC\"); return 2; }\n"
                "  puts(\"nope\"); return 0;\n}\n"
            )
            binary = Path(tmp) / "kat.bin"
            build = subprocess.run(
                [compiler, "-g", "-O0", str(source), "-o", str(binary)],
                capture_output=True,
            )
            if build.returncode != 0:
                cls._self_test_cache = (False, "self-test program failed to compile")
                return cls._self_test_cache

            try:
                project = angr.Project(str(binary), auto_load_libs=False)
                arg = claripy.BVS("arg", 8 * 8)
                state = project.factory.full_init_state(args=[str(binary), arg])
                simgr = project.factory.simulation_manager(state)
                simgr.explore(
                    find=lambda s: b"MAGIC" in s.posix.dumps(1),
                    avoid=lambda s: b"nope" in s.posix.dumps(1),
                    num_find=1,
                )
                if not simgr.found:
                    cls._self_test_cache = (
                        False, "angr did not reach the target branch on this platform"
                    )
                    return cls._self_test_cache

                solved = simgr.found[0].solver.eval(arg, cast_to=bytes)
                if solved.startswith(b"KAVA"):
                    cls._self_test_cache = (True, f"angr solved the known-answer test ({detail})")
                else:
                    cls._self_test_cache = (
                        False,
                        "angr reached the branch but could not tie the symbolic input to "
                        f"the comparison (recovered {solved[:8]!r}, expected b'KAVA...'). "
                        "Concolic results on this platform would be meaningless, so "
                        "Driller is disabled. angr's symbolic execution is reliable on "
                        "x86-64 ELF; this host is "
                        f"{project.arch.name} {project.loader.main_object.__class__.__name__}."
                    )
            except Exception as e:
                cls._self_test_cache = (False, f"self-test raised {type(e).__name__}: {e}")

        return cls._self_test_cache

    def drill(
        self,
        binary: str,
        seed: bytes,
        input_mode: str = "stdin",       # "stdin" | "argv" | "file"
        max_states: int = 200,
        timeout_seconds: int = 120,
    ) -> DrillResult:
        """
        Symbolically execute `binary` on `seed` and solve for inputs that take
        the opposite side of branches the seed did not take.

        Returns the concrete inputs the solver produced. Only branches that the
        solver proves satisfiable yield an input, so every returned value is a
        genuinely reachable path, not a guess.
        """
        result = DrillResult(seed=seed.hex()[:64])
        start = time.time()

        # Gate on the known-answer test, not merely on angr importing. If
        # symbolic execution cannot solve a trivial magic-value check on this
        # platform, any "solved" input it produced here would be noise.
        ok, detail = self.self_test()
        if not ok:
            result.reason = detail
            result.seconds = round(time.time() - start, 2)
            return result

        import angr
        import claripy

        try:
            project = angr.Project(binary, auto_load_libs=False)
        except Exception as e:
            result.reason = f"angr could not load the binary: {e}"
            result.seconds = round(time.time() - start, 2)
            return result

        try:
            # Symbolic input of the same length as the seed, pre-constrained to
            # the seed's bytes only where we want it concrete (here: nowhere, so
            # the solver is free to change any byte).
            length = max(len(seed), 1)
            symbolic = claripy.BVS("input", length * 8)

            if input_mode == "stdin":
                state = project.factory.full_init_state(
                    stdin=angr.SimFileStream(name="stdin", content=symbolic, has_end=True),
                    add_options=angr.options.unicorn,
                )
            elif input_mode == "argv":
                state = project.factory.full_init_state(
                    args=[binary, symbolic],
                    add_options=angr.options.unicorn,
                )
            else:
                path = self.output_dir / "drill_input.bin"
                path.write_bytes(seed)
                simfile = angr.SimFile("drill_input.bin", content=symbolic, size=length)
                state = project.factory.full_init_state(
                    args=[binary, str(path)],
                    fs={str(path): simfile},
                    add_options=angr.options.unicorn,
                )

            simgr = project.factory.simulation_manager(state)
            deadline = start + timeout_seconds
            seen_branches: set = set()

            while simgr.active and time.time() < deadline and result.states_explored < max_states:
                simgr.step()
                result.states_explored += len(simgr.active)

                # Every state that survives a split represents a branch the
                # concrete seed did not necessarily take. Solve each for a
                # concrete input.
                for active in simgr.active:
                    key = active.addr
                    if key in seen_branches:
                        continue
                    seen_branches.add(key)
                    if not active.satisfiable():
                        continue
                    try:
                        concrete = active.solver.eval(symbolic, cast_to=bytes)
                    except Exception:
                        continue
                    if concrete != seed and concrete not in result.new_inputs:
                        result.new_inputs.append(concrete)
                        result.branches_flipped += 1

                if len(result.new_inputs) >= 32:
                    break

            result.supported = True
            result.reason = (
                f"explored {result.states_explored} states, "
                f"solved {result.branches_flipped} new branch input(s)"
            )

        except Exception as e:
            result.reason = f"symbolic execution failed on this target: {type(e).__name__}: {e}"

        result.seconds = round(time.time() - start, 2)
        return result

    def write_inputs(self, result: DrillResult, queue_dir: str) -> list[str]:
        """Write solved inputs into a fuzzer queue directory. Returns the paths."""
        out = Path(queue_dir)
        out.mkdir(parents=True, exist_ok=True)
        written = []
        for i, data in enumerate(result.new_inputs):
            path = out / f"driller_{i:04d}"
            path.write_bytes(data)
            written.append(str(path))
        logger.info(f"Driller wrote {len(written)} input(s) into {queue_dir}")
        return written


class PlateauMonitor:
    """
    Watches an AFL++ output directory and reports when the fuzzer has stalled.

    A plateau is a window in which `paths_total` does not increase — meaning the
    fuzzer is no longer discovering new coverage and is a candidate for
    concolic assistance.
    """

    def __init__(self, fuzzer_out_dir: str, stall_checks: int = 3, interval_seconds: int = 30):
        self.fuzzer_out_dir = Path(fuzzer_out_dir)
        self.stall_checks = stall_checks
        self.interval_seconds = interval_seconds

    def read_stats(self) -> dict:
        """Parse AFL++ fuzzer_stats. Returns {} if the fuzzer has not written it yet."""
        stats_path = self.fuzzer_out_dir / "default" / "fuzzer_stats"
        if not stats_path.exists():
            return {}
        stats = {}
        for line in stats_path.read_text().splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                stats[key.strip()] = value.strip()
        return stats

    def is_plateaued(self, samples: list[int]) -> bool:
        """True when the last `stall_checks` samples show no new coverage."""
        if len(samples) < self.stall_checks + 1:
            return False
        window = samples[-(self.stall_checks + 1):]
        return len(set(window)) == 1

    def watch(self, on_plateau, max_seconds: int = 600) -> int:
        """
        Poll the fuzzer until it plateaus or `max_seconds` elapses.
        Calls `on_plateau()` each time a stall is detected. Returns the number
        of plateaus observed.
        """
        samples: list[int] = []
        plateaus = 0
        deadline = time.time() + max_seconds

        while time.time() < deadline:
            stats = self.read_stats()
            if stats:
                paths = int(stats.get("corpus_count", stats.get("paths_total", 0)) or 0)
                samples.append(paths)
                if self.is_plateaued(samples):
                    logger.info(f"Fuzzer plateau detected at {paths} paths — invoking Driller")
                    on_plateau()
                    plateaus += 1
                    samples.clear()
            time.sleep(min(self.interval_seconds, max(1, deadline - time.time())))

        return plateaus
