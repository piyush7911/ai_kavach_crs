"""Managed runner for a Gradle Spring-Boot target — build the (patched) app and run it on a free port,
health-check it, stop it. This is what lets the Java repair loop test a patch: each attempt rebuilds the
patched source. The Java counterpart of src/pyauto/runner.py.

Unlike the interpreted backends, Java must COMPILE, so a gate attempt costs a Gradle build. We build a
bootJar (incremental with the Gradle daemon) and run it as `java -jar`, which is a clean child process the
group-kill can stop reliably (a bare `gradlew bootRun` leaves the app under the daemon)."""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class JavaAppServer:
    tree: Path
    context_path: str = ""              # e.g. /VulnerableApp (server.servlet.context-path)
    health_path: str = "/"
    port: int = 0
    build_timeout: float = 300.0
    _proc: subprocess.Popen | None = field(default=None, repr=False)

    def __post_init__(self):
        self.tree = Path(self.tree).resolve()          # absolute: Popen cwd=tree must not double the path

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _gradlew(self) -> str:
        return str(self.tree / ("gradlew.bat" if os.name == "nt" else "gradlew"))

    def start(self, health_timeout: float = 90.0) -> "JavaAppServer":
        self.port = self.port or _free_port()
        # 1. build the patched jar (incremental; the daemon keeps this to seconds after the first build)
        build = subprocess.run([self._gradlew(), "bootJar", "-q", "--console=plain"],
                               cwd=self.tree, capture_output=True, text=True, timeout=self.build_timeout)
        if build.returncode != 0:
            raise RuntimeError(f"gradle build failed (rc={build.returncode}): {build.stderr[-500:] or build.stdout[-500:]}")
        jars = [p for p in (self.tree / "build" / "libs").glob("*.jar") if not p.name.endswith("-plain.jar")]
        if not jars:
            raise RuntimeError("no bootJar produced in build/libs")
        jar = max(jars, key=lambda p: p.stat().st_mtime)
        # 2. run it as a clean child process on the chosen port
        self._proc = subprocess.Popen(["java", "-jar", str(jar), f"--server.port={self.port}"],
                                      cwd=self.tree, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      start_new_session=True)
        url = self.base_url + self.context_path + self.health_path
        deadline = time.monotonic() + health_timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"java app exited early (rc={self._proc.returncode})")
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    if r.status < 500:
                        return self
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        self.stop()
        raise TimeoutError(f"java app not healthy on {url} in {health_timeout}s")

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                return
            for _ in range(30):
                if self._proc.poll() is not None:
                    return
                time.sleep(0.1)
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def __enter__(self) -> "JavaAppServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
