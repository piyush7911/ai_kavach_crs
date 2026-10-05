"""
Run a command from the autonomous mode, through the sandbox, and keep the output.

Every execution of code that came from an uploaded repository goes through this
function: compiling it, fuzzing it, replaying an input on it. It exists so there
is exactly one place where that happens, and that place respects the sandbox.

Differences from `DRVLoop._run`, which the repair gates use:

  * the FULL stdout and stderr are returned. Parsing a fuzzer's coverage report
    or a sanitizer's stack needs all of it; `_run` trims for model feedback;
  * the timeout is the caller's, because a fuzz campaign is not a 180 s gate;
  * what the sandbox actually did (`backend`, `note`) is returned and recorded,
    so a result never claims confinement that did not happen.

Mode: autonomous mode defaults to ``KAVACH_SANDBOX=required``. If no backend
exists the command is NOT run and the result says why. A developer working on
trusted code can opt out explicitly with ``KAVACH_SANDBOX=off``.
"""

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.patch_validator import sandbox


def default_to_required() -> None:
    """Autonomous mode runs untrusted code, so unconfined execution must be an explicit choice."""
    os.environ.setdefault("KAVACH_SANDBOX", "required")


@dataclass
class ExecResult:
    ok: bool                 # exit code 0
    code: Optional[int]      # None if the command never ran or timed out
    stdout: str = ""
    stderr: str = ""
    seconds: float = 0.0
    timed_out: bool = False
    ran: bool = True         # False when the sandbox refused to run it
    backend: str = ""        # "sandbox-exec" | "bwrap" | "none"
    note: str = ""

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def run(command: str, cwd: Path, timeout: int = 120, env: Optional[dict] = None) -> ExecResult:
    """Run a shell command in `cwd` under the configured sandbox."""
    cwd = Path(cwd)
    cwd.mkdir(parents=True, exist_ok=True)
    base = dict(os.environ)
    # The sanitizer settings every gate uses. Leak checking at process exit would
    # turn one-off allocations in a library's own code into failures.
    base.update({"ASAN_OPTIONS": "detect_leaks=0", "MallocNanoZone": "0"})
    base.update(env or {})

    try:
        plan = sandbox.plan(command, cwd, base)
    except sandbox.SandboxUnavailable as e:
        return ExecResult(ok=False, code=None, ran=False, backend="none", note=str(e))

    started = time.time()
    try:
        p = subprocess.run(plan.argv, cwd=str(cwd), env=plan.env, capture_output=True,
                           text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired as e:
        return ExecResult(
            ok=False, code=None, timed_out=True, seconds=round(time.time() - started, 2),
            stdout=(e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            stderr=(e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
            backend=plan.backend, note=plan.note)

    return ExecResult(ok=p.returncode == 0, code=p.returncode, stdout=p.stdout, stderr=p.stderr,
                      seconds=round(time.time() - started, 2),
                      backend=plan.backend, note=plan.note)
