"""
AI Kavach CRS — Fuzzer Manager

Builds and runs coverage-guided fuzzing campaigns against a target, using a
single libFuzzer-style harness (`LLVMFuzzerTestOneInput`) that both supported
engines can drive:

  * **libFuzzer** — in-process, needs a clang that ships the fuzzer runtime.
    On macOS the Apple clang does NOT; Homebrew LLVM does, and is auto-detected.
  * **AFL++** — out-of-process, driven through `tests/fuzz_harnesses/afl_driver.c`,
    which reads AFL's `@@` input file and calls the same harness entry point.

Both build with AddressSanitizer + UndefinedBehaviorSanitizer so that memory
errors become observable crashes rather than silent corruption.

Platform note: on macOS, AFL++ needs a constrained coverage map
(`AFL_MAP_SIZE`) because the default SysV shared-memory limits
(`kern.sysv.shmall` = 1024 pages) are too small for AFL's default. This class
sets it automatically. If `shmget` still fails, run `sudo afl-system-config`.
"""

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SAN_FLAGS = [
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-fno-omit-frame-pointer",
    "-g", "-O1",
]

# Homebrew LLVM ships libclang_rt.fuzzer_osx.a; Apple's command-line clang does not.
_LLVM_CANDIDATES = [
    "/opt/homebrew/opt/llvm/bin/clang",
    "/usr/local/opt/llvm/bin/clang",
]


@dataclass
class FuzzCampaignResult:
    """Outcome of one fuzzing campaign — all fields are observed, not estimated."""

    engine: str
    target_id: str
    duration_seconds: float
    executions: int = 0
    crashes: list[str] = field(default_factory=list)
    build_ok: bool = False
    build_error: str = ""
    run_error: str = ""
    binary: str = ""

    @property
    def crash_count(self) -> int:
        return len(self.crashes)


class FuzzerManager:
    """Builds fuzz targets and runs campaigns with libFuzzer or AFL++."""

    def __init__(self, workspace_dir: str, harness_dir: str = "tests/fuzz_harnesses"):
        # Absolute throughout: campaigns run with cwd set to the findings
        # directory, so any relative path would break once the engine starts.
        self.workspace_dir = Path(workspace_dir).resolve()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.harness_dir = Path(harness_dir).resolve()

    # -- capability detection ----------------------------------------------

    @staticmethod
    def libfuzzer_clang() -> Optional[str]:
        """Path to a clang whose runtime includes libFuzzer, or None."""
        for candidate in _LLVM_CANDIDATES:
            if Path(candidate).exists():
                return candidate
        clang = shutil.which("clang")
        if clang and FuzzerManager._has_fuzzer_runtime(clang):
            return clang
        return None

    @staticmethod
    def _has_fuzzer_runtime(clang: str) -> bool:
        probe = Path(os.environ.get("TMPDIR", "/tmp")) / "kavach_fuzz_probe.c"
        probe.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){(void)d;(void)s;return 0;}\n"
        )
        out = probe.with_suffix(".bin")
        try:
            result = subprocess.run(
                [clang, "-fsanitize=fuzzer", str(probe), "-o", str(out)],
                capture_output=True, timeout=120,
            )
            return result.returncode == 0
        except Exception:
            return False
        finally:
            probe.unlink(missing_ok=True)
            out.unlink(missing_ok=True)

    @staticmethod
    def afl_available() -> bool:
        return bool(shutil.which("afl-fuzz")) and bool(shutil.which("afl-clang-fast"))

    def available_engines(self) -> list[str]:
        engines = []
        if self.libfuzzer_clang():
            engines.append("libfuzzer")
        if self.afl_available():
            engines.append("afl++")
        return engines

    # -- building ----------------------------------------------------------

    def build(self, target_id: str, source_file: str, engine: str) -> tuple[Optional[Path], str]:
        """
        Compile harness + target into a fuzzable binary.

        The target's own `main` is renamed away (-Dmain=…) so it does not clash
        with the fuzzer's entry point, while the vulnerable function stays
        exactly as written.
        """
        harness = self.harness_dir / f"{target_id}.c"
        if not harness.exists():
            return None, f"no fuzz harness for {target_id} (expected {harness})"

        out_dir = self.workspace_dir / target_id / engine
        out_dir.mkdir(parents=True, exist_ok=True)
        binary = out_dir / "fuzz_target"

        if engine == "libfuzzer":
            clang = self.libfuzzer_clang()
            if not clang:
                return None, "no clang with a libFuzzer runtime found"
            cmd = [
                clang, "-fsanitize=fuzzer,address,undefined",
                "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-g", "-O1",
                f"-Dmain=kavach_disabled_main_{target_id.replace('-', '_')}",
                str(harness), source_file, "-o", str(binary),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                return None, result.stderr[:2000]
            return binary, ""

        if engine == "afl++":
            if not self.afl_available():
                return None, "afl-fuzz / afl-clang-fast not on PATH"
            env = dict(os.environ, AFL_USE_ASAN="1", AFL_USE_UBSAN="1", AFL_QUIET="1")
            objects = []
            # The target is compiled separately so that -Dmain only renames ITS
            # main, not the driver's.
            units = [
                (source_file, [f"-Dmain=kavach_disabled_main_{target_id.replace('-', '_')}"]),
                (str(harness), []),
                (str(self.harness_dir / "afl_driver.c"), []),
            ]
            for i, (src, extra) in enumerate(units):
                obj = out_dir / f"unit{i}.o"
                result = subprocess.run(
                    ["afl-clang-fast", "-g", "-O1", "-c", *extra, src, "-o", str(obj)],
                    capture_output=True, text=True, env=env, timeout=300,
                )
                if result.returncode != 0:
                    return None, result.stderr[:2000]
                objects.append(str(obj))

            result = subprocess.run(
                ["afl-clang-fast", "-g", "-O1", *objects, "-o", str(binary)],
                capture_output=True, text=True, env=env, timeout=300,
            )
            if result.returncode != 0:
                return None, result.stderr[:2000]
            return binary, ""

        return None, f"unknown engine: {engine}"

    # -- running -----------------------------------------------------------

    def run_campaign(
        self,
        target_id: str,
        source_file: str,
        engine: str = "libfuzzer",
        seconds: int = 30,
        seed_dir: Optional[str] = None,
    ) -> FuzzCampaignResult:
        """Build the target and fuzz it for `seconds`, returning observed crashes."""
        import time

        result = FuzzCampaignResult(engine=engine, target_id=target_id, duration_seconds=0.0)

        source_file = str(Path(source_file).resolve())
        binary, error = self.build(target_id, source_file, engine)
        if binary is None:
            result.build_error = error
            logger.error(f"[{target_id}] fuzz build failed ({engine}): {error[:200]}")
            return result
        result.build_ok = True
        result.binary = str(binary)

        seeds = Path(seed_dir) if seed_dir else self.harness_dir / "seeds"
        out_dir = binary.parent / "findings"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)

        start = time.time()
        if engine == "libfuzzer":
            self._run_libfuzzer(binary, seeds, out_dir, seconds, result)
        else:
            self._run_afl(binary, seeds, out_dir, seconds, result)
        result.duration_seconds = round(time.time() - start, 2)

        logger.info(
            f"[{target_id}] {engine}: {result.crash_count} crash input(s) "
            f"in {result.duration_seconds}s"
        )
        return result

    def _run_libfuzzer(self, binary, seeds, out_dir, seconds, result):
        corpus = out_dir / "corpus"
        corpus.mkdir(exist_ok=True)
        artifacts = out_dir / "crashes"
        artifacts.mkdir(exist_ok=True)

        cmd = [
            str(binary),
            str(corpus), str(seeds),
            f"-max_total_time={seconds}",
            f"-artifact_prefix={artifacts}/",
            "-print_final_stats=1",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=seconds + 120,
                env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0", MallocNanoZone="0"),
                cwd=str(out_dir),
            )
            output = proc.stderr.decode("utf-8", "replace")
            for line in output.splitlines():
                if "stat::number_of_executed_units:" in line:
                    result.executions = int(line.split(":")[-1].strip())
        except subprocess.TimeoutExpired:
            result.run_error = "libFuzzer exceeded its wall-clock budget"

        result.crashes = [str(p) for p in artifacts.iterdir() if p.is_file()]

    def _run_afl(self, binary, seeds, out_dir, seconds, result):
        # macOS SysV shm limits require a small map; harmless elsewhere.
        env = dict(
            os.environ,
            AFL_MAP_SIZE="65536",
            AFL_SKIP_CPUFREQ="1",
            AFL_NO_AFFINITY="1",
            AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1",
            AFL_QUIET="1",
            ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=0",
        )
        cmd = [
            "afl-fuzz", "-i", str(seeds), "-o", str(out_dir),
            "-V", str(seconds), "-m", "none", "--", str(binary), "@@",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=seconds + 180, env=env)
            if proc.returncode != 0:
                result.run_error = proc.stderr.decode("utf-8", "replace")[-1500:]
        except subprocess.TimeoutExpired:
            result.run_error = "afl-fuzz exceeded its wall-clock budget"

        stats = out_dir / "default" / "fuzzer_stats"
        if stats.exists():
            for line in stats.read_text().splitlines():
                if line.startswith("execs_done"):
                    result.executions = int(line.split(":")[1].strip())

        for crashes_dir in out_dir.rglob("crashes"):
            for crash in crashes_dir.iterdir():
                if crash.is_file() and not crash.name.startswith("README"):
                    result.crashes.append(str(crash))
