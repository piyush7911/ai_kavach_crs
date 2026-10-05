"""Start and stop a Node web app (NodeGoat or a customized variant) in isolation.

Each run gets its own free TCP port and its own MongoDB database, binds to loopback
only (via loopback_preload.js), seeds the database if the tree ships a seed script,
health-checks the app, and tears everything down — including dropping the per-run
database — on stop. Nothing here reads a manifest or hard-codes a vulnerability; it
only knows how to *run* an app tree, so it works on an app we have not seen.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

try:  # shared sandbox (Track 2's module); optional so the runner works without it
    from src.patch_validator import sandbox as _sandbox
except Exception:  # noqa: BLE001
    _sandbox = None

HERE = Path(__file__).resolve().parent
PRELOAD = HERE / "loopback_preload.js"
# Mongo reachable only from this machine; overridable for a different host/port.
MONGO_BASE = os.environ.get("KAVACH_NODEGOAT_MONGO", "mongodb://127.0.0.1:27017")
HEALTH_PATHS = ("/login", "/")
NODE = os.environ.get("KAVACH_NODE", "node")


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _main_script(tree: Path) -> str:
    try:
        return json.loads((tree / "package.json").read_text()).get("main", "server.js")
    except (OSError, ValueError):
        return "server.js"


@dataclass
class AppServer:
    tree: Path
    port: int = 0
    db_name: str = ""
    boot_seconds: float = 0.0
    sandbox_note: str = "sandbox off"
    _proc: subprocess.Popen | None = field(default=None, repr=False)
    _log: Path | None = field(default=None, repr=False)

    def _wrap(self, argv: list[str], env: dict) -> tuple[list[str], dict]:
        """Apply the shared loopback sandbox to a node command when enabled.

        The app binds its own port and talks to Mongo on 127.0.0.1; every other
        network destination is denied, and writes are confined to the tree.
        """
        if _sandbox is None or _sandbox.mode() == "off":
            return argv, env
        p = _sandbox.plan(shlex.join(argv), self.tree, env,
                          allow_loopback=True)
        self.sandbox_note = f"{p.backend}: {p.note}"
        return p.argv, p.env

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def mongo_uri(self) -> str:
        return f"{MONGO_BASE}/{self.db_name}"

    def _env(self) -> dict:
        env = dict(os.environ)
        env.update(MONGODB_URI=self.mongo_uri, PORT=str(self.port))
        # Keep NODE_ENV as the caller set it (default: unset → development).
        return env

    def _db_reachable(self) -> bool:
        host, port = "127.0.0.1", 27017
        m = re.search(r"//([^:/]+):(\d+)", MONGO_BASE)
        if m:
            host, port = m.group(1), int(m.group(2))
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(2)
            return s.connect_ex((host, port)) == 0

    def _seed(self, timeout: int = 60) -> None:
        seed = self.tree / "artifacts" / "db-reset.js"
        if not seed.exists():
            return
        if not self._db_reachable():
            # A dead DB otherwise surfaces as an opaque "db seed failed rc=1" and looks
            # like a broken patch. Fail distinctly so the real cause is obvious.
            raise RuntimeError(
                f"MongoDB not reachable at {MONGO_BASE} — start it before running "
                f"(sh tools/mongo.sh start, or docker start kavach-mongo44). "
                f"This is an environment problem, not a patch failure.")
        argv, env = self._wrap([NODE, str(seed)], self._env())
        r = subprocess.run(argv, cwd=self.tree, env=env,
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f"db seed failed (rc={r.returncode}): {r.stderr[-500:]}")

    def start(self, health_timeout: float = 25.0, log_dir: Path | None = None) -> "AppServer":
        if not self.tree.is_dir():
            raise FileNotFoundError(f"app tree not found: {self.tree}")
        self.port = self.port or _free_port()
        self.db_name = self.db_name or f"nodegoat_run_{secrets.token_hex(5)}"
        self._seed()
        log_dir = log_dir or Path(os.environ.get("TMPDIR", "/tmp"))
        self._log = log_dir / f"{self.db_name}.log"
        main = _main_script(self.tree)
        argv, env = self._wrap([NODE, "--require", str(PRELOAD), main], self._env())
        t0 = time.monotonic()
        with open(self._log, "wb") as logf:
            self._proc = subprocess.Popen(
                argv, cwd=self.tree, env=env, stdout=logf, stderr=subprocess.STDOUT,
                start_new_session=True,  # own process group → clean group kill
            )
        self._await_health(health_timeout, t0)
        return self

    def _await_health(self, timeout: float, t0: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc and self._proc.poll() is not None:
                raise RuntimeError(f"app exited early (rc={self._proc.returncode}):\n{self._log_tail()}")
            for path in HEALTH_PATHS:
                try:
                    with urllib.request.urlopen(self.base_url + path, timeout=2) as resp:
                        if resp.status == 200:
                            self.boot_seconds = round(time.monotonic() - t0, 2)
                            return
                except (urllib.error.URLError, ConnectionError, socket.timeout):
                    pass
            time.sleep(0.25)
        self.stop()
        raise TimeoutError(f"app did not become healthy in {timeout}s:\n{self._log_tail()}")

    def _log_tail(self, n: int = 1500) -> str:
        try:
            return self._log.read_text(errors="replace")[-n:] if self._log else ""
        except OSError:
            return ""

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._wait(3)
            except ProcessLookupError:
                pass
            if self._proc.poll() is None:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self._drop_db()

    def _wait(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self._proc.poll() is None:
            time.sleep(0.1)

    def _drop_db(self) -> None:
        # Best effort: use the tree's own mongodb driver so we need no extra tool.
        if not self.db_name:
            return
        script = (
            "const {MongoClient}=require('mongodb');"
            f"MongoClient.connect('{self.mongo_uri}',{{useNewUrlParser:true,useUnifiedTopology:true}},"
            "(e,c)=>{if(e){process.exit(0)}c.db().dropDatabase(()=>{c.close();process.exit(0)})});"
        )
        try:
            subprocess.run([NODE, "-e", script], cwd=self.tree, env=self._env(),
                           capture_output=True, timeout=15)
        except (subprocess.SubprocessError, OSError):
            pass

    def __enter__(self) -> "AppServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
