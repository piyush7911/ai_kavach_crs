"""
AI Kavach — live dashboard (FastAPI).

One server, one static page, no build step. It shows what the system measured,
runs the benchmark and the special-case checks on demand, and accepts a
repository by drag-and-drop.

    python -m dashboard                 # http://127.0.0.1:8000
    python -m dashboard --port 9000

Rules this file enforces
------------------------
* **It displays only what a run produced.** Results come from artefacts on
  disk; progress comes from the event stream; a missing result is an empty
  state, never a placeholder.
* **Browser input never reaches a shell.** Jobs are argument lists built from
  whitelisted choices; free-text fields are validated against a strict pattern.
* **One heavy job at a time**, with the busy state surfaced to the UI.
* **Localhost by default.** Set KAVACH_DASH_TOKEN to require a token when the
  server is bound to a network interface.
"""

import asyncio
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from dashboard import health, results, uploads
from dashboard.jobs import BusyError, JobManager, strip_ansi
from src.events import read_events

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"

PY = sys.executable
SUITES = {"synthetic", "juliet", "real_world", "real_cve", "all", "fuzz"}
_SAFE_LIST = re.compile(r"^[A-Za-z0-9_:\-,.]{1,400}$")
_SAFE_MODEL = re.compile(r"^[A-Za-z0-9_.:\-/]{1,80}$")

jobs = JobManager()


# -- auth (optional) ----------------------------------------------------------

def require_token(request: Request) -> None:
    token = os.getenv("KAVACH_DASH_TOKEN")
    if not token:
        return
    supplied = request.headers.get("x-token") or request.query_params.get("token")
    if supplied != token:
        raise HTTPException(status_code=401, detail="token required")


api = APIRouter(prefix="/api", dependencies=[Depends(require_token)])


# -- request models -------------------------------------------------------------

class BenchmarkRequest(BaseModel):
    suite: str = "synthetic"
    harden: bool = True
    formal: bool = False
    memory: bool = False
    fuzz: bool = False
    fuzz_seconds: int = Field(30, ge=5, le=300)
    only: str = ""
    limit: Optional[int] = Field(None, ge=1, le=100)
    provider: str = "cloud"
    model: str = ""


class ProviderRequest(BaseModel):
    provider: str = "cloud"
    model: str = ""


def provider_env(provider: str, model: str) -> dict:
    """Environment for a run on the chosen provider. Cloud inherits the project's .env."""
    if provider not in ("cloud", "local"):
        raise HTTPException(400, "provider must be 'cloud' or 'local'")
    if model and not _SAFE_MODEL.match(model):
        raise HTTPException(400, "invalid model name")
    if provider == "cloud":
        return {}
    status = health.ollama_status()
    if not status["reachable"]:
        raise HTTPException(409, "local model server is not reachable "
                                 f"at {status['url']} (is `ollama serve` running?)")
    chosen = model or health.LOCAL_MODEL
    if chosen not in [m["name"] for m in status["models"]]:
        raise HTTPException(409, f"model '{chosen}' is not installed locally")
    return {
        "OPENAI_BASE_URL": f"{health.OLLAMA_URL}/v1",
        "OPENAI_API_KEY": "ollama",                  # Ollama ignores it; the client requires one
        "MODEL_ALPHA": chosen, "MODEL_BETA": chosen, "MODEL_GAMMA": chosen,
    }


def _launch(kind, argv, title, env=None, meta=None, events_flag=None):
    try:
        job = jobs.start(kind, argv, title, extra_env=env, meta=meta, events_flag=events_flag)
    except BusyError as e:
        raise HTTPException(409, f"busy: {e}")
    return job.to_dict()


# -- health + results -------------------------------------------------------------

@api.get("/health")
def get_health(force: bool = False):
    return health.collect(force=force)


@api.get("/results/runs")
def get_runs():
    runs = results.list_runs()
    default = results.default_run_id(runs)
    for r in runs:
        r["full"] = r["targets"] >= results.FULL_RUN_MIN_TARGETS
        r["default"] = r["id"] == default
    return runs


@api.get("/results/headline")
def get_headline(run: Optional[str] = None):
    if run and not re.fullmatch(r"[0-9_]+", run):
        raise HTTPException(400, "invalid run id")
    return results.headline(run)


@api.get("/results/run/{run_id}")
def get_run(run_id: str):
    detail = results.run_detail(run_id)
    if detail is None:
        raise HTTPException(404, "run not found")
    return {"id": run_id, "targets": detail["targets"], "preflight": detail["preflight"]}


@api.get("/special/{name}")
def get_special(name: str):
    data = results.special_result(name)
    if data is None:
        return JSONResponse({"empty": True}, status_code=200)
    return data


# -- jobs -----------------------------------------------------------------------------

@api.get("/jobs/current")
def current_job():
    job = jobs.current
    if not job:
        return {"job": None}
    d = job.to_dict()
    return {"job": d, "progress": jobs.progress(job)}


@api.get("/jobs/history")
def job_history():
    return jobs.history()


@api.get("/jobs/{job_id}")
def get_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return {"job": job.to_dict(), "progress": jobs.progress(job),
            "log": jobs.log_tail(job), "events": read_events(job.events_path)}


@api.post("/jobs/{job_id}/stop")
def stop_job(job_id: str):
    if not jobs.stop(job_id):
        raise HTTPException(404, "no such running job")
    return {"stopped": job_id}


@api.post("/jobs/benchmark")
def start_benchmark(req: BenchmarkRequest):
    if req.suite not in SUITES:
        raise HTTPException(400, f"suite must be one of {sorted(SUITES)}")
    if req.only and not _SAFE_LIST.match(req.only):
        raise HTTPException(400, "invalid target filter")
    env = provider_env(req.provider, req.model)

    argv = [PY, "benchmark.py", "--suite", req.suite]
    if req.harden:
        argv.append("--harden")
    if req.formal:
        argv.append("--formal")
    if req.memory:
        argv.append("--memory")
    if req.fuzz and req.suite != "fuzz":
        argv += ["--fuzz"]
    if req.suite == "fuzz" or req.fuzz:
        argv += ["--fuzz-seconds", str(req.fuzz_seconds)]
    if req.only:
        argv += ["--only", req.only]
    if req.limit:
        argv += ["--limit", str(req.limit)]

    label = "local model" if req.provider == "local" else "cloud API"
    return _launch("benchmark", argv, f"Benchmark: {req.suite} ({label})", env,
                   {"suite": req.suite, "provider": req.provider,
                    "model": env.get("MODEL_BETA", "cloud default"),
                    "harden": req.harden, "formal": req.formal, "only": req.only},
                   events_flag="--events")


@api.post("/jobs/cheat")
def start_cheat():
    out = PROJECT_ROOT / "reports" / "special" / "cheat_detector.json"
    return _launch("cheat", [PY, "-m", "tests.cheat_detector.run_cheat_detector", "--json", str(out)],
                   "Cheat detector", meta={"special": "cheat_detector"})


@api.post("/jobs/redteam")
def start_redteam():
    out = PROJECT_ROOT / "reports" / "special" / "redteam.json"
    return _launch("redteam", [PY, "-m", "tests.cheat_detector.run_redteam", "--json", str(out)],
                   "Verifier red-team", meta={"special": "redteam"})


@api.post("/jobs/unittests")
def start_unit_tests():
    return _launch("unittests", [PY, "-m", "pytest", "tests/unit", "-q"], "Unit tests",
                   meta={"special": "unittests"})


@api.post("/jobs/preflight")
def start_preflight():
    return _launch("preflight", [PY, "-m", "dashboard.tasks.preflight"],
                   "PoV pre-flight (all targets)", meta={"special": "preflight"},
                   events_flag="--events")


@api.post("/jobs/modelcheck")
def start_modelcheck(req: ProviderRequest):
    env = provider_env(req.provider, req.model)
    label = "local model" if req.provider == "local" else "cloud API"
    return _launch("modelcheck", [PY, "-m", "dashboard.tasks.modelcheck"],
                   f"Model check ({label})", env,
                   {"special": "modelcheck", "provider": req.provider},
                   events_flag="--events")


class AutoRequest(BaseModel):
    repo_id: str
    llm_harness: bool = True
    max_functions: int = Field(5, ge=1, le=20)
    fuzz_seconds: int = Field(0, ge=0, le=600)     # 0 = harness only, nothing is compiled or run
    repair: bool = False
    provider: str = "cloud"
    model: str = ""


@api.post("/jobs/auto")
def start_auto(req: AutoRequest):
    """
    Autonomous mode on an uploaded repository. No free-text command is accepted
    from the browser: the repository is chosen by id and everything else is a
    whitelisted flag. With fuzz_seconds > 0 the upload IS compiled and run, under
    KAVACH_SANDBOX=required (network denied, writes confined to the run directory).
    """
    if importlib.util.find_spec("src.autonomy") is None:
        raise HTTPException(501, "autonomous mode is not installed")
    info = uploads.describe(req.repo_id)
    if not info:
        raise HTTPException(404, "repository not found")
    env = provider_env(req.provider, req.model) if req.llm_harness else {}
    run_dir = PROJECT_ROOT / "reports" / "auto_runs" / req.repo_id
    argv = [PY, "-m", "src.main", "--mode", "auto",
            "--target", str(PROJECT_ROOT / info["root"]),
            "--run-dir", str(run_dir), "--max-functions", str(req.max_functions)]
    if not req.llm_harness:
        argv.append("--no-llm-harness")
    if req.fuzz_seconds:
        argv += ["--fuzz-seconds", str(req.fuzz_seconds)]
    if req.repair:
        argv.append("--repair")
        env = {**env, **provider_env(req.provider, req.model)}     # repair needs a model even if harness drafting is off
    return _launch("auto", argv, f"Auto mode: {info['name']}", env,
                   {"special": "auto", "repo_id": req.repo_id, "run_dir": str(run_dir)},
                   events_flag="--events")


@api.get("/auto/{repo_id}")
def get_auto_evidence(repo_id: str):
    if not re.fullmatch(r"r_[0-9]{8}_[0-9]{6}_[0-9a-f]{4}", repo_id):
        raise HTTPException(400, "invalid repo id")
    path = PROJECT_ROOT / "reports" / "auto_runs" / repo_id / "evidence.json"
    if not path.exists():
        raise HTTPException(404, "no auto-mode run for this repository yet")
    return json.loads(path.read_text())


@api.get("/capabilities")
def capabilities():
    return {"auto_mode": importlib.util.find_spec("src.autonomy") is not None,
            "token_required": bool(os.getenv("KAVACH_DASH_TOKEN"))}


@api.get("/jobs/{job_id}/stream")
async def stream_job(job_id: str):
    """Server-sent events: log chunks, new structured events, progress, and the end."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")

    async def gen():
        log_pos, last_seq = 0, 0
        while True:
            chunk = ""
            if job.log_path.exists():
                with open(job.log_path, "rb") as f:
                    f.seek(log_pos)
                    raw = f.read()
                    log_pos += len(raw)
                chunk = strip_ansi(raw.decode(errors="replace"))
            if chunk:
                yield f"event: log\ndata: {json.dumps({'text': chunk})}\n\n"
            new = read_events(job.events_path, after_seq=last_seq)
            for e in new:
                last_seq = e["seq"]
                yield f"event: evt\ndata: {json.dumps(e)}\n\n"
            if new:
                yield f"event: progress\ndata: {json.dumps(jobs.progress(job))}\n\n"
            yield f"event: status\ndata: {json.dumps(job.to_dict())}\n\n"
            if not job.running and not chunk and not new:
                yield f"event: end\ndata: {json.dumps(job.to_dict())}\n\n"
                return
            await asyncio.sleep(0.7)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -- repositories (drag and drop) ----------------------------------------------------------

@api.post("/repos")
async def upload_repo(files: list[UploadFile] = File(...), paths: list[str] = Form(default=[])):
    """
    Accept a zip archive, or a dropped folder as many files with relative paths.
    The files are landed safely and described; nothing is built or run here.
    """
    repo_id, dest = uploads.new_repo_dir()
    try:
        is_zip = len(files) == 1 and not paths and (files[0].filename or "").lower().endswith(".zip")
        if is_zip:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                size = 0
                while chunk := await files[0].read(1 << 20):
                    size += len(chunk)
                    if size > uploads.MAX_TOTAL_BYTES:
                        raise uploads.UploadError("zip file is too large")
                    tmp.write(chunk)
            try:
                uploads.extract_zip(Path(tmp.name), dest)
            finally:
                Path(tmp.name).unlink(missing_ok=True)
        else:
            if paths and len(paths) != len(files):
                raise uploads.UploadError("every file needs a path")
            state: dict = {}
            for i, f in enumerate(files):
                rel = paths[i] if paths else (f.filename or "")
                uploads.write_dropped_file(dest, rel, await f.read(), state)
    except uploads.UploadError as e:
        uploads.delete_repo(repo_id)
        raise HTTPException(400, str(e))
    except Exception:
        uploads.delete_repo(repo_id)
        raise

    info = uploads.describe(repo_id)
    if not info or info["census"]["source_files"] == 0:
        uploads.delete_repo(repo_id)
        raise HTTPException(400, "no C or C++ source files found in the upload")
    return info


@api.get("/repos")
def get_repos():
    return uploads.list_repos()


@api.get("/repos/{repo_id}")
def get_repo(repo_id: str):
    info = uploads.describe(repo_id)
    if not info:
        raise HTTPException(404, "repository not found")
    return info


@api.delete("/repos/{repo_id}")
def remove_repo(repo_id: str):
    if not uploads.delete_repo(repo_id):
        raise HTTPException(404, "repository not found")
    return {"deleted": repo_id}


# -- app ------------------------------------------------------------------------------------

app = FastAPI(title="AI Kavach — live dashboard", docs_url="/api/docs", redoc_url=None,
              openapi_url="/api/openapi.json")
app.include_router(api)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
