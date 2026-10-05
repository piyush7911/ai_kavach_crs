"""
AI Kavach CRS — process sandbox for gate commands.

Build, PoV and regression commands compile and run code that came from the
target — for an uploaded repository, code nobody on our side has read. This
module wraps those commands so that, while they run:

  * **network access is denied**, and
  * **file writes are confined** to the gate's workspace (plus /dev, for
    /dev/null and friends). Reads are not restricted: compilers need the SDK,
    headers and toolchain wherever they are installed.

Backends, chosen by platform:

  * macOS: `sandbox-exec` with an SBPL profile generated per workspace.
  * Linux: `bwrap` (bubblewrap) — read-only root, the workspace bind-mounted
    writable, a private /tmp, and a fresh network namespace.

Mode is read from the environment variable ``KAVACH_SANDBOX``:

  ``off``       (default) commands run as before. The benchmark corpus is our
                own code; its results were measured unsandboxed and stay
                comparable.
  ``auto``      sandbox when a backend exists; otherwise run unsandboxed and
                record that it did not happen.
  ``required``  sandbox or refuse: if no backend exists the command is not run
                and the gate fails with the reason. Autonomous mode on an
                uploaded repository uses this.

What this does *not* claim: it is a policy enforced by the OS sandbox the
platform provides, not a VM. It does not limit CPU or memory (the gate timeout
bounds time), and it does not stop a command from reading files the user can
read. Say exactly that, and show the denial test, rather than "air-gapped".
"""

import os
import platform
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

MODE_OFF = "off"
MODE_AUTO = "auto"
MODE_REQUIRED = "required"
_MODES = (MODE_OFF, MODE_AUTO, MODE_REQUIRED)


class SandboxUnavailable(RuntimeError):
    """Mode is `required` but this machine has no sandbox backend."""


@dataclass
class SandboxPlan:
    """How one command will actually be run. Recorded, never inferred later."""

    backend: str            # "sandbox-exec" | "bwrap" | "none"
    argv: list[str]         # what to execute (no shell=True wrapping needed)
    env: dict
    note: str = ""

    @property
    def sandboxed(self) -> bool:
        return self.backend != "none"


def mode() -> str:
    value = os.environ.get("KAVACH_SANDBOX", MODE_OFF).strip().lower()
    return value if value in _MODES else MODE_OFF


def backend() -> Optional[str]:
    """The sandbox backend available on this machine, or None."""
    system = platform.system()
    if system == "Darwin" and shutil.which("sandbox-exec"):
        return "sandbox-exec"
    if system == "Linux" and shutil.which("bwrap"):
        return "bwrap"
    return None


def _sbpl_quote(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def macos_profile(writable: list[str]) -> str:
    """
    SBPL profile: everything allowed except network and writes outside
    `writable`. Paths must be real paths (/private/var/..., not /var/...):
    sandbox-exec matches after symlink resolution.
    """
    allowed = "\n".join(f"    (subpath {_sbpl_quote(p)})" for p in writable)
    return (
        "(version 1)\n"
        "(allow default)\n"
        "(deny network*)\n"
        "(deny file-write*)\n"
        "(allow file-write*\n"
        f"{allowed}\n"
        '    (literal "/dev/null")\n'
        '    (literal "/dev/zero")\n'
        '    (literal "/dev/tty")\n'
        '    (regex #"^/dev/fd/")\n'
        '    (regex #"^/dev/ttys"))\n'
    )


def plan(command: str, workspace: Path, env: dict,
         extra_writable: Optional[list[str]] = None) -> SandboxPlan:
    """
    Decide how to run `command` (a shell string) for a gate in `workspace`.

    Raises SandboxUnavailable when the mode is `required` and no backend exists.
    """
    current = mode()
    sh = ["/bin/sh", "-c", command]
    if current == MODE_OFF:
        return SandboxPlan("none", sh, env, "sandbox off")

    found = backend()
    if found is None:
        if current == MODE_REQUIRED:
            raise SandboxUnavailable(
                "KAVACH_SANDBOX=required but no sandbox backend is available "
                "(need sandbox-exec on macOS or bwrap on Linux)"
            )
        return SandboxPlan("none", sh, env, "no sandbox backend on this machine")

    ws = os.path.realpath(str(workspace))
    writable = [ws] + [os.path.realpath(p) for p in (extra_writable or [])]
    # Tools that honour TMPDIR (clang, the linker, Python) write their scratch
    # files inside the workspace instead of the per-user temp directory, which
    # the profile does not allow.
    tmp = Path(ws) / ".tmp"
    tmp.mkdir(exist_ok=True)
    env = dict(env, TMPDIR=str(tmp))

    if found == "sandbox-exec":
        argv = ["sandbox-exec", "-p", macos_profile(writable), *sh]
        return SandboxPlan(found, argv, env, f"network denied; writes limited to {ws}")

    argv = [
        "bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
        "--tmpfs", "/tmp",
    ]
    for p in writable:
        argv += ["--bind", p, p]
    argv += ["--unshare-net", "--die-with-parent", "--chdir", ws, *sh]
    return SandboxPlan(found, argv, env, f"network denied; writes limited to {ws}")


def describe() -> dict:
    """What the sandbox would do on this machine, for health and evidence output."""
    return {"mode": mode(), "backend": backend() or "none",
            "denies": ["network", "file writes outside the gate workspace"],
            "does_not_limit": ["file reads", "CPU", "memory"]}


def shell_quote(argv: list[str]) -> str:
    """Printable form of a plan's argv, for logs (the profile is elided)."""
    shown = []
    skip = False
    for i, a in enumerate(argv):
        if skip:
            shown.append("<profile>")
            skip = False
            continue
        if a == "-p" and i > 0 and argv[i - 1] == "sandbox-exec":
            shown.append(a)
            skip = True
            continue
        shown.append(shlex.quote(a))
    return " ".join(shown)
