"""
Job manager for the dashboard.

Runs one long task at a time (benchmark, cheat detector, tests, ...) as a
subprocess, and exposes its log, its structured events and a measured resource
peak.

Design rules
------------
* **One job at a time.** The machine is a single laptop; two heavy runs at once
  would corrupt each other's timing and memory measurements, which this project
  publishes. The lock is explicit and the UI shows a "busy" state.
* **Arguments are lists, never shell strings.** Nothing a browser sends is ever
  interpolated into a shell command.
* **Everything shown is something that happened.** The log is the process's
  real output; events are written by the instrumented code; the resource peak
  is sampled from the OS. Nothing is synthesised.
"""

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from dashboard.health import ollama_memory_mb
from src.events import read_events

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = PROJECT_ROOT / "dashboard" / "runs"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def tree_rss_mb(root_pid: int) -> float:
    """Resident memory of a process and all its descendants, from `ps`."""
    try:
        out = subprocess.run(
            ["ps", "-A", "-o", "pid=,ppid=,rss="],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return 0.0
    children: dict[int, list[int]] = {}
    rss: dict[int, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        pid, ppid, kb = (int(x) for x in parts)
        children.setdefault(ppid, []).append(pid)
        rss[pid] = kb
    total, stack, seen = 0, [root_pid], set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        total += rss.get(pid, 0)
        stack.extend(children.get(pid, []))
    return round(total / 1024, 1)


class BusyError(RuntimeError):
    """Raised when a job is requested while another is running."""


class Job:
    def __init__(self, kind: str, argv: list[str], env: dict, title: str, meta: dict):
        self.id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:4]
        self.kind = kind
        self.argv = argv
        self.title = title
        self.meta = meta
        self.dir = RUNS_DIR / self.id
        self.log_path = self.dir / "log.txt"
        self.events_path = self.dir / "events.jsonl"
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self.exit_code: Optional[int] = None
        self.stopped = False
        self.peak_rss_mb = 0.0
        # Resident memory of the local model server, sampled only for jobs that
        # actually talk to it. None means "not applicable", never zero.
        self.peak_model_server_mb: Optional[float] = None
        self.proc: Optional[subprocess.Popen] = None
        self._env = env

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def code(self) -> Optional[int]:
        """Exit code, read from the process itself if the watcher has not recorded it yet."""
        if self.exit_code is not None:
            return self.exit_code
        if self.proc is not None and self.proc.poll() is not None:
            return self.proc.returncode
        return None

    @property
    def status(self) -> str:
        if self.running:
            return "running"
        if self.stopped:
            return "stopped"
        code = self.code
        if code is None:
            return "starting"          # only true before the process exists
        return "done" if code == 0 else "failed"

    def to_dict(self) -> dict:
        end = self.ended_at or time.time()
        return {
            "id": self.id, "kind": self.kind, "title": self.title,
            "status": self.status, "exit_code": self.code,
            "started_at": self.started_at, "ended_at": self.ended_at,
            "elapsed_s": round(end - self.started_at, 1),
            "peak_rss_mb": self.peak_rss_mb,
            "peak_model_server_mb": self.peak_model_server_mb,
            "meta": self.meta,
        }


class JobManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.current: Optional[Job] = None
        self._jobs: dict[str, Job] = {}
        RUNS_DIR.mkdir(parents=True, exist_ok=True)

    # -- lifecycle ----------------------------------------------------------

    def start(self, kind: str, argv: list[str], title: str, extra_env: Optional[dict] = None,
              meta: Optional[dict] = None, events_flag: Optional[str] = None) -> Job:
        """
        Launch a job. `events_flag`, if given, is the CLI option that takes the
        events file path (e.g. "--events"); it is appended automatically so the
        instrumented program writes where we read.
        """
        with self._lock:
            if self.current and self.current.running:
                raise BusyError(f"'{self.current.title}' is still running")

            env = dict(os.environ)
            env.update({"PYTHONUNBUFFERED": "1", "NO_COLOR": "1", "TERM": "dumb"})
            env.update(extra_env or {})

            job = Job(kind, list(argv), env, title, meta or {})
            job.dir.mkdir(parents=True, exist_ok=True)
            if events_flag:
                job.argv += [events_flag, str(job.events_path)]

            log = open(job.log_path, "w")
            job.proc = subprocess.Popen(
                job.argv, cwd=str(PROJECT_ROOT), env=env,
                stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True,           # own process group, so Stop kills children too
            )
            self.current = job
            self._jobs[job.id] = job
            self._write_meta(job)

        threading.Thread(target=self._watch, args=(job, log), daemon=True).start()
        return job

    def _watch(self, job: Job, log) -> None:
        """Sample memory while the job runs; record the exit."""
        uses_local = "localhost" in job._env.get("OPENAI_BASE_URL", "") or "127.0.0.1" in job._env.get("OPENAI_BASE_URL", "")
        if uses_local:
            job.peak_model_server_mb = 0.0
        while job.proc.poll() is None:
            job.peak_rss_mb = max(job.peak_rss_mb, tree_rss_mb(job.proc.pid))
            if uses_local:
                job.peak_model_server_mb = max(job.peak_model_server_mb, ollama_memory_mb())
            time.sleep(1.5)
        job.exit_code = job.proc.returncode
        job.ended_at = time.time()
        log.close()
        self._write_meta(job)

    def stop(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or not job.running:
            return False
        job.stopped = True
        try:
            os.killpg(os.getpgid(job.proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        return True

    def _write_meta(self, job: Job) -> None:
        try:
            (job.dir / "meta.json").write_text(json.dumps(job.to_dict(), indent=2))
        except OSError:
            pass

    # -- reading ------------------------------------------------------------

    def get(self, job_id: str) -> Optional[Job]:
        if job_id in self._jobs:
            return self._jobs[job_id]
        meta_path = RUNS_DIR / job_id / "meta.json"
        if not meta_path.exists():
            return None
        # A job from an earlier server session: read-only view reconstructed from disk.
        data = json.loads(meta_path.read_text())
        job = Job(data["kind"], [], {}, data["title"], data.get("meta", {}))
        job.id = job_id
        job.dir = RUNS_DIR / job_id
        job.log_path, job.events_path = job.dir / "log.txt", job.dir / "events.jsonl"
        job.started_at, job.ended_at = data["started_at"], data.get("ended_at")
        job.exit_code = data.get("exit_code")
        job.peak_rss_mb = data.get("peak_rss_mb", 0.0)
        job.peak_model_server_mb = data.get("peak_model_server_mb")
        job.stopped = data.get("status") == "stopped"
        return job

    def history(self, limit: int = 15) -> list[dict]:
        out = []
        for d in sorted(RUNS_DIR.iterdir(), reverse=True)[:limit * 2]:
            job = self.get(d.name)
            if job:
                out.append(job.to_dict())
            if len(out) >= limit:
                break
        return out

    @staticmethod
    def log_tail(job: Job, max_chars: int = 20000) -> str:
        if not job.log_path.exists():
            return ""
        text = job.log_path.read_text(errors="replace")
        return strip_ansi(text[-max_chars:])

    @staticmethod
    def progress(job: Job) -> dict:
        """Derive progress from the event stream only."""
        suites: dict[str, dict] = {}
        done = total = 0
        current = ""
        for e in read_events(job.events_path):
            d = e.get("data", {})
            kind = e["kind"]
            if kind == "suite_start":
                suites[d["suite"]] = {"suite": d["suite"], "total": d["total"], "done": 0, "patched": 0}
                total += d["total"]
            elif kind == "target_start":
                current = d.get("id", "")
            elif kind in ("target_done", "fuzz_result"):
                s = suites.get(d.get("suite"))
                if s:
                    s["done"] += 1
                    if kind == "target_done" and d.get("result") == "patched":
                        s["patched"] += 1
                    if kind == "fuzz_result":
                        s["patched"] += d.get("fixed", 0)
                done += 1
                current = ""
        return {"done": done, "total": total, "current": current,
                "suites": list(suites.values())}
