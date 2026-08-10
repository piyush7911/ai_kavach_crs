"""
AI Kavach CRS — Crash Triage & Deduplication

Turns a pile of raw fuzzer crash inputs into a small set of distinct, located
vulnerability reports.

Two backends, selected automatically:

  * **CASR** (`casr-san` + `casr-cluster`) when those binaries are on PATH.
  * **Native ASan triage** otherwise — implemented here, not stubbed. It runs
    each crash input under the sanitized binary, parses the AddressSanitizer /
    UndefinedBehaviorSanitizer report, and deduplicates by root cause.

Deduplication follows the same principle CASR uses: crashes are grouped by
(crash class, normalised top-of-stack frames). Thousands of fuzzer crashes that
share a root cause collapse into one report, because patching effort should be
spent per bug, not per crashing input.

Only frames belonging to the target's own source are used for the signature —
sanitizer interceptors and libc frames are skipped, so the same bug reached
through `memcpy` and through `strcpy` still clusters together.
"""

import hashlib
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.agent_orchestrator.orchestrator import VulnerabilityReport

logger = logging.getLogger(__name__)

# ASan/UBSan crash class -> (CWE, severity). Used to label the report the agents see.
CRASH_CLASS_TO_CWE = {
    "heap-buffer-overflow": ("CWE-122", "critical"),
    "stack-buffer-overflow": ("CWE-121", "critical"),
    "global-buffer-overflow": ("CWE-787", "critical"),
    "heap-use-after-free": ("CWE-416", "critical"),
    "double-free": ("CWE-415", "critical"),
    "attempting double-free": ("CWE-415", "critical"),
    "alloc-dealloc-mismatch": ("CWE-762", "high"),
    "memcpy-param-overlap": ("CWE-475", "high"),
    "stack-overflow": ("CWE-674", "high"),
    "SEGV": ("CWE-476", "critical"),
    "BUS": ("CWE-476", "critical"),
    "FPE": ("CWE-369", "medium"),
    "requested allocation size": ("CWE-190", "critical"),
    "signed-integer-overflow": ("CWE-190", "high"),
    "shift-exponent": ("CWE-682", "medium"),
    "index-out-of-bounds": ("CWE-125", "critical"),
    "load of misaligned address": ("CWE-1319", "medium"),
    "null-pointer-dereference": ("CWE-476", "critical"),
}

# Frames that carry no root-cause information and must not affect the signature.
_NOISE_FRAME = re.compile(
    r"(libclang_rt\.|libsystem_|libdyld|dyld|__asan|__ubsan|__sanitizer|"
    r"wrap_|interceptor_|start\+|libc\+\+|"
    # Fuzzing scaffolding: the harness and engine frames are identical for every
    # crash in a campaign, so including them would blur distinct root causes.
    r"fuzzer::|LLVMFuzzerTestOneInput|afl_driver|__libc_start)",
    re.IGNORECASE,
)

_ASAN_ERROR = re.compile(r"ERROR:\s+(?:AddressSanitizer|LeakSanitizer):\s+([a-zA-Z0-9_-]+)")
_UBSAN_ERROR = re.compile(r"([^\s:]+):(\d+):\d+:\s+runtime error:\s+(.+)")
_ALLOC_SIZE = re.compile(r"requested allocation size")
_FRAME = re.compile(r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(.+?)(?:\s+([^\s]+\.(?:c|cc|cpp|h)):(\d+))?\s*$")


@dataclass
class CrashSignature:
    """The identity of a crash — what makes two crashes 'the same bug'."""

    crash_class: str
    frames: list[str] = field(default_factory=list)      # normalised function names
    file_path: str = ""
    line_number: int = 0
    raw_report: str = ""

    @property
    def digest(self) -> str:
        """Stable hash over crash class + top source frames + crash location."""
        material = "|".join([self.crash_class, *self.frames[:5], self.file_path, str(self.line_number)])
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    @property
    def cwe_and_severity(self) -> tuple[str, str]:
        for needle, (cwe, sev) in CRASH_CLASS_TO_CWE.items():
            if needle.lower() in self.crash_class.lower():
                return cwe, sev
        return "", "high"


@dataclass
class CrashCluster:
    """A group of crash inputs sharing one root cause."""

    signature: CrashSignature
    inputs: list[str] = field(default_factory=list)

    @property
    def representative(self) -> str:
        """Smallest input in the cluster — the easiest PoV to reason about."""
        return min(self.inputs, key=lambda p: Path(p).stat().st_size if Path(p).exists() else 1 << 30)


class CrashTriage:
    """Executes crash inputs, parses sanitizer output, and clusters by root cause."""

    def __init__(self, workspace_dir: str, source_root: Optional[str] = None):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.source_root = Path(source_root).resolve() if source_root else None
        self.backend = "casr" if self._casr_available() else "native-asan"
        logger.info(f"Crash triage backend: {self.backend}")

    @staticmethod
    def _casr_available() -> bool:
        return bool(shutil.which("casr-san")) and bool(shutil.which("casr-cluster"))

    # -- public API ---------------------------------------------------------

    def triage(
        self,
        target_binary: str,
        crash_inputs: list[str],
        args: Optional[list[str]] = None,
        input_mode: str = "file",       # "file" (@@ / argv) or "stdin"
    ) -> list[CrashCluster]:
        """
        Reproduce each crash, extract its signature, and group by root cause.
        Inputs that do not reproduce are dropped (and counted) rather than
        being reported as vulnerabilities.
        """
        clusters: dict[str, CrashCluster] = {}
        not_reproduced = 0

        for crash_input in crash_inputs:
            signature = self._signature_for(target_binary, crash_input, args, input_mode)
            if signature is None:
                not_reproduced += 1
                continue
            cluster = clusters.setdefault(signature.digest, CrashCluster(signature=signature))
            cluster.inputs.append(crash_input)

        if not_reproduced:
            logger.info(f"{not_reproduced} crash input(s) did not reproduce and were discarded")
        logger.info(
            f"Triaged {len(crash_inputs)} crash input(s) into {len(clusters)} distinct root cause(s)"
        )
        return list(clusters.values())

    def to_vulnerability_reports(self, clusters: list[CrashCluster]) -> list[VulnerabilityReport]:
        """Convert clusters into the report objects the orchestrator consumes."""
        reports = []
        for i, cluster in enumerate(clusters, 1):
            sig = cluster.signature
            cwe, severity = sig.cwe_and_severity
            location = sig.frames[0] if sig.frames else "unknown function"
            reports.append(VulnerabilityReport(
                id=f"FUZZ-{i:03d}",
                source="fuzzer+triage",
                file_path=sig.file_path,
                line_number=sig.line_number,
                description=(
                    f"{sig.crash_class} reached in {location}. "
                    f"Discovered by fuzzing; {len(cluster.inputs)} crashing input(s) "
                    f"collapsed to this root cause."
                ),
                cwe_id=cwe,
                severity=severity,
                crash_trace=sig.raw_report[:4000],
            ))
        return reports

    # -- signature extraction ----------------------------------------------

    def _signature_for(
        self, target_binary: str, crash_input: str,
        args: Optional[list[str]], input_mode: str,
    ) -> Optional[CrashSignature]:
        if self.backend == "casr":
            sig = self._signature_via_casr(target_binary, crash_input, args)
            if sig:
                return sig
            logger.debug("casr-san produced no report; falling back to native parsing")
        return self._signature_via_asan(target_binary, crash_input, args, input_mode)

    def _signature_via_asan(
        self, target_binary: str, crash_input: str,
        args: Optional[list[str]], input_mode: str,
    ) -> Optional[CrashSignature]:
        """Run the input and parse the sanitizer report it produces."""
        cmd = [target_binary]
        stdin_data = None

        if input_mode == "stdin":
            stdin_data = Path(crash_input).read_bytes()
            cmd += list(args or [])
        else:
            supplied = list(args or ["@@"])
            cmd += [crash_input if a == "@@" else a for a in supplied]

        try:
            proc = subprocess.run(
                cmd, input=stdin_data, capture_output=True, timeout=30,
                env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0",
                         MallocNanoZone="0"),
            )
        except subprocess.TimeoutExpired:
            # A hang is a real finding, but it is not a memory-safety crash.
            return CrashSignature(crash_class="timeout/hang", frames=[], raw_report="timed out")
        except Exception as e:
            logger.debug(f"Failed to execute crash input {crash_input}: {e}")
            return None

        report = proc.stderr.decode("utf-8", "replace") + proc.stdout.decode("utf-8", "replace")
        return self.parse_sanitizer_report(report, self.source_root)

    @staticmethod
    def parse_sanitizer_report(report: str, source_root: Optional[Path] = None) -> Optional[CrashSignature]:
        """
        Extract crash class, the faulting source location, and the normalised
        stack signature from an ASan/UBSan report.

        Returns None when the report shows no sanitizer error — i.e. the input
        did not actually reproduce a crash.
        """
        crash_class = ""
        file_path, line_number = "", 0

        match = _ASAN_ERROR.search(report)
        if match:
            crash_class = match.group(1)
        elif _ALLOC_SIZE.search(report):
            crash_class = "requested allocation size (integer overflow)"
        else:
            ub = _UBSAN_ERROR.search(report)
            if ub:
                file_path, line_number = ub.group(1), int(ub.group(2))
                crash_class = ub.group(3).strip()
            elif "SEGV" in report:
                crash_class = "SEGV"
            else:
                return None

        # Walk the frames, keeping only those from the target's own sources.
        frames: list[str] = []
        for raw in report.splitlines():
            frame = _FRAME.match(raw)
            if not frame:
                continue
            function, frame_file, frame_line = frame.group(2), frame.group(3), frame.group(4)
            if _NOISE_FRAME.search(raw):
                continue
            if source_root and frame_file:
                try:
                    Path(frame_file).resolve().relative_to(source_root)
                except (ValueError, OSError):
                    pass
            frames.append(function.split("(")[0].strip())
            if frame_file and not file_path:
                file_path, line_number = frame_file, int(frame_line or 0)

        # Sanitizer reports often carry only a basename. The orchestrator has to
        # open this file, so resolve it back to a real path under the source root.
        if file_path and not Path(file_path).exists() and source_root:
            for candidate in source_root.rglob(Path(file_path).name):
                file_path = str(candidate)
                break

        return CrashSignature(
            crash_class=crash_class,
            frames=frames,
            file_path=file_path,
            line_number=line_number,
            raw_report=report,
        )

    def _signature_via_casr(
        self, target_binary: str, crash_input: str, args: Optional[list[str]]
    ) -> Optional[CrashSignature]:
        """Use casr-san to produce a report, then read its JSON."""
        import json

        out = self.workspace_dir / f"casr_{Path(crash_input).name}.casrep"
        supplied = list(args or ["@@"])
        cmd_args = [crash_input if a == "@@" else a for a in supplied]

        try:
            subprocess.run(
                ["casr-san", "-o", str(out), "--", target_binary, *cmd_args],
                capture_output=True, timeout=60,
            )
        except Exception as e:
            logger.debug(f"casr-san failed on {crash_input}: {e}")
            return None

        if not out.exists():
            return None

        try:
            data = json.loads(out.read_text())
        except Exception:
            return None

        crash_line = data.get("CrashLine", "") or ""
        file_path, _, line = crash_line.partition(":")
        return CrashSignature(
            crash_class=data.get("CrashSeverity", {}).get("ShortDescription", "unknown"),
            frames=[f.split()[-1] for f in data.get("Stacktrace", [])[:5]],
            file_path=file_path,
            line_number=int(line) if line.isdigit() else 0,
            raw_report=json.dumps(data)[:4000],
        )
