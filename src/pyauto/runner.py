"""Managed runner for a Python web target — start a (patched) copy on a free loopback port, seed
it, health-check it, stop it. This is what lets the repair loop test a patch: each attempt runs the
patched tree, not the original. The Python counterpart of the Node AppServer.

The start command is a template with {port}; it is the one app-specific bit (for a connexion/Flask
app like VAmPI: `python -c "import config; config.vuln_app.run(host='127.0.0.1', port={port})"`,
which bypasses a hard-coded port with no code change).
"""
from __future__ import annotations

import os
import shlex
import signal
import socket
import subprocess
import time
import urllib.request
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class PyAppServer:
    tree: Path
    start_cmd: str                      # template with {port}
    env: dict = field(default_factory=dict)
    seed_path: str | None = None        # HTTP GET to reset state (VAmPI: /createdb)
    health_path: str = "/"
    port: int = 0
    _proc: subprocess.Popen | None = field(default=None, repr=False)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, health_timeout: float = 25.0) -> "PyAppServer":
        self.port = self.port or _free_port()
        env = {**os.environ, **self.env}
        cmd = shlex.split(self.start_cmd.format(port=self.port))
        self._proc = subprocess.Popen(cmd, cwd=self.tree, env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      start_new_session=True)
        deadline = time.monotonic() + health_timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"python app exited early (rc={self._proc.returncode})")
            try:
                with urllib.request.urlopen(self.base_url + self.health_path, timeout=2) as r:
                    if r.status < 500:
                        break
            except (urllib.error.URLError, OSError):
                time.sleep(0.3)
        else:
            self.stop()
            raise TimeoutError(f"python app not healthy on {self.base_url} in {health_timeout}s")
        if self.seed_path:
            try:
                urllib.request.urlopen(self.base_url + self.seed_path, timeout=15).read()
            except (urllib.error.URLError, OSError) as e:
                raise RuntimeError(f"seed {self.seed_path} failed: {e}") from e
        return self

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                return
            for _ in range(20):
                if self._proc.poll() is not None:
                    return
                time.sleep(0.1)
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def __enter__(self) -> "PyAppServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
