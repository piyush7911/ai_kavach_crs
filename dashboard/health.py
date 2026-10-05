"""
System health for the dashboard: which tools are present, what the machine is,
which model provider is configured, and whether a local model is reachable.

Every value is a live probe. A tool that is missing is reported missing, with
the reason, rather than assumed. API keys are never returned, only whether one
is set.
"""

import json
import os
import platform
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OLLAMA_URL = os.getenv("OLLAMA_HOST_URL", "http://localhost:11434")
LOCAL_MODEL = os.getenv("KAVACH_LOCAL_MODEL", "kavach-coder:7b")

_cache: dict = {"at": 0.0, "value": None}
CACHE_SECONDS = 15


def _run(cmd: list[str], timeout: float = 6.0) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, "not found"
    except subprocess.TimeoutExpired:
        return False, "timed out"
    except Exception as e:                              # pragma: no cover - defensive
        return False, f"{type(e).__name__}: {e}"
    text = (p.stdout or p.stderr or "").strip()
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    return p.returncode == 0 or bool(first), first[:140]


def _tool(name: str, cmd: list[str], role: str, required: bool = True) -> dict:
    path = shutil.which(cmd[0])
    if not path:
        return {"name": name, "role": role, "ok": False, "version": "", "detail": "not installed",
                "required": required}
    ok, line = _run(cmd)
    return {"name": name, "role": role, "ok": ok, "version": line, "detail": path,
            "required": required}


def _http_json(url: str, timeout: float = 1.5) -> Optional[dict]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def ollama_status() -> dict:
    """Is a local model server reachable, and which models does it hold?"""
    ver = _http_json(f"{OLLAMA_URL}/api/version")
    if ver is None:
        return {"reachable": False, "version": "", "models": [], "default_model_present": False,
                "url": OLLAMA_URL, "default_model": LOCAL_MODEL}
    tags = _http_json(f"{OLLAMA_URL}/api/tags") or {}
    models = [{"name": m.get("name", ""), "size_gb": round(m.get("size", 0) / 1e9, 1)}
              for m in tags.get("models", []) if m.get("size", 0) > 0]
    return {"reachable": True, "version": ver.get("version", ""), "models": models,
            "default_model": LOCAL_MODEL, "url": OLLAMA_URL,
            "default_model_present": any(m["name"].split(":")[0] == LOCAL_MODEL.split(":")[0]
                                         and m["name"] == LOCAL_MODEL for m in models)}


def ollama_memory_mb() -> float:
    """
    Memory held by models currently loaded in Ollama (weights + KV cache), in MB.

    Asked of Ollama itself via /api/ps, NOT read from `ps`. On Apple Silicon the
    weights live in GPU-visible unified memory and do not appear in a process's
    RSS: measured here, `ps` showed 24 MB for a model Ollama reports as 4.77 GiB.
    Using RSS would have understated a local run's footprint by about 99%.
    """
    ps = _http_json(f"{OLLAMA_URL}/api/ps")
    if not ps:
        return 0.0
    return round(sum(m.get("size", 0) for m in ps.get("models", [])) / 2**20, 1)


def machine_info() -> dict:
    info = {"platform": f"{platform.system()} {platform.machine()}",
            "python": platform.python_version(), "chip": "", "ram_gb": None}
    if platform.system() == "Darwin":
        ok, chip = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if ok:
            info["chip"] = chip
        ok, mem = _run(["sysctl", "-n", "hw.memsize"])
        if ok and mem.isdigit():
            info["ram_gb"] = round(int(mem) / 2**30)
    else:
        info["chip"] = platform.processor() or ""
        try:
            pages, size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
            info["ram_gb"] = round(pages * size / 2**30)
        except (ValueError, OSError, AttributeError):
            pass
    return info


def provider_info() -> dict:
    """Which model backend a run would use by default. Never returns the key."""
    try:
        from config import get_llm_config
        cfg = get_llm_config()
        base, models, has_key = cfg["base_url"], cfg["models"], True
    except Exception:
        base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        models, has_key = {}, bool(os.getenv("OPENAI_API_KEY"))
    local = "localhost" in base or "127.0.0.1" in base
    return {"base_url": base, "is_local": local, "api_key_set": has_key,
            "models": models, "label": "Local model" if local else "Cloud API"}


def collect(force: bool = False) -> dict:
    now = time.time()
    if not force and _cache["value"] and now - _cache["at"] < CACHE_SECONDS:
        return _cache["value"]

    from src.analysis_engine.fuzzer_manager import FuzzerManager

    libfuzzer = FuzzerManager.libfuzzer_clang()
    tools = [
        _tool("clang", ["clang", "--version"], "Compiler + sanitizers (ASan, UBSan)"),
        {"name": "libFuzzer", "role": "Coverage-guided fuzzing (needs a clang that ships the runtime)",
         "ok": bool(libfuzzer), "version": "", "detail": libfuzzer or "no clang with the fuzzer runtime",
         "required": True},
        _tool("AFL++", ["afl-fuzz", "-h"], "Alternate fuzzing engine", required=False),
        _tool("Semgrep", ["semgrep", "--version"], "Static analysis (SARIF)"),
        _tool("CBMC", ["cbmc", "--version"], "Bounded model checking", required=False),
        _tool("sandbox-exec", ["sandbox-exec", "-n", "no-network", "true"],
              "Process sandbox (macOS)", required=False),
    ]
    for t in tools:
        if t["name"] == "AFL++" and t["ok"]:
            t["version"] = "available"            # afl-fuzz -h prints usage, not a version
        if t["name"] == "sandbox-exec":
            t["ok"] = shutil.which("sandbox-exec") is not None
            t["version"] = "available" if t["ok"] else ""

    value = {
        "generated_at": now,
        "tools": tools,
        "machine": machine_info(),
        "provider": provider_info(),
        "ollama": ollama_status(),
    }
    value["ready"] = all(t["ok"] for t in tools if t["required"])
    _cache.update(at=now, value=value)
    return value
