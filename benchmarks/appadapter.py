"""Per-app adapter: everything app-specific about running a target, so the language-neutral
runner (replay / regress / harden) can drive ANY web app, not just NodeGoat.

An app is described by a small JSON config:

    {
      "name": "vampi",
      "mode": "external",                        # the app is already running (e.g. in Docker)
      "base_url": "http://127.0.0.1:5001",
      "health_path": "/",
      "seed": {"method": "GET", "path": "/createdb"},   # reset state before each run
      "auth": { ...the Session auth spec... }           # how a role logs in; injected into exploits
    }

`mode: "managed"` is the NodeGoat path (the runner's AppServer starts/seeds/stops a Node tree);
nothing in this file is used then. `mode: "external"` is for an app started outside the runner:
this adapter just seeds it over HTTP, health-checks it, and hands its base_url + auth to the oracles.
The exploit/regression/hardening/metamorphic oracles are unchanged — only auth and start differ.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AppConfig:
    name: str
    mode: str = "managed"                 # managed (Node tree via AppServer) | external (already running)
    base_url: str = ""
    health_path: str = "/"
    seed: dict | None = None              # {"method","path"} HTTP seed, or None
    auth: dict | None = None              # Session auth spec, injected into every exploit

    @staticmethod
    def load(path: str | Path) -> "AppConfig":
        d = json.loads(Path(path).read_text())
        return AppConfig(name=d["name"], mode=d.get("mode", "managed"),
                         base_url=d.get("base_url", ""), health_path=d.get("health_path", "/"),
                         seed=d.get("seed"), auth=d.get("auth"))


@dataclass
class ExternalApp:
    """An app the runner does not start (external mode): seed over HTTP, health-check, reuse. Mirrors
    the slice of AppServer the runner needs (base_url / start / stop), so the runner treats both alike."""
    config: AppConfig
    boot_seconds: float = 0.0
    sandbox_note: str = "external app (not managed)"
    _field: dict = field(default_factory=dict, repr=False)

    @property
    def base_url(self) -> str:
        return self.config.base_url.rstrip("/")

    def start(self, health_timeout: float = 20.0, **_) -> "ExternalApp":
        t0 = time.monotonic()
        deadline = t0 + health_timeout
        url = self.base_url + self.config.health_path
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    if r.status < 500:
                        break
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        else:
            raise TimeoutError(f"external app not healthy at {url} in {health_timeout}s")
        if self.config.seed:
            s = self.config.seed
            req = urllib.request.Request(self.base_url + s["path"], method=s.get("method", "GET"))
            try:
                urllib.request.urlopen(req, timeout=15).read()
            except (urllib.error.URLError, OSError) as e:
                raise RuntimeError(f"seed {s} failed: {e}") from e
        self.boot_seconds = round(time.monotonic() - t0, 2)
        return self

    def stop(self) -> None:
        pass  # external app lifecycle is not ours


def with_auth(exploit: dict, config: AppConfig | None) -> dict:
    """Inject the app's auth into an exploit unless it already carries one."""
    if config and config.auth and "auth" not in exploit:
        return {**exploit, "auth": config.auth}
    return exploit
