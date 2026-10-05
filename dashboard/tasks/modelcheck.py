"""
Model readiness check: can the configured provider do what the pipeline needs,
and how fast?

Measures, on whichever provider the environment selects (cloud or local):

  * a repair-shaped request on a real target, with a warm-up first so model
    load time is not mistaken for generation speed;
  * the Critic's strict JSON-schema call, which is the feature most likely to
    differ between servers;
  * output tokens per second, from the provider's own token counts.

    python -m dashboard.tasks.modelcheck [--events PATH]
"""

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agent_orchestrator.llm_client import LLMClient
from src.agent_orchestrator.critic import CRITIC_SCHEMA, CRITIC_SYSTEM_PROMPT
from dashboard.health import ollama_memory_mb
from src.events import EventSink, NULL_SINK

TARGET = PROJECT_ROOT / "tests" / "demo_vulns" / "06_off_by_one_loop.c"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="")
    args = ap.parse_args()
    sink = EventSink(args.events) if args.events else NULL_SINK

    client = LLMClient()
    base = client.client.base_url
    host = urlparse(str(base)).netloc
    model = client.models["beta"]
    is_local = "localhost" in host or "127.0.0.1" in host
    result = {"generated_at": time.time(), "provider": "local" if is_local else "cloud",
              "host": host, "model": model}
    sink.emit("run_start", stage="modelcheck", status="info",
              message=f"checking {model} on {host}")

    # Warm-up: loads the model into memory. Not counted.
    sink.emit("stage", stage="warmup", status="info", message="loading model (not timed)")
    try:
        client.generate_patch("beta", "Reply with the single word: ready")
    except Exception as e:
        result.update(ok=False, error=f"{type(e).__name__}: {str(e)[:240]}")
        _write(result)
        sink.emit("run_done", stage="run", status="fail", message=result["error"])
        print("FAILED:", result["error"], flush=True)
        return 1

    prompt = ("VULNERABILITY: heap-buffer-overflow (CWE-193) in copy_and_null_terminate: "
              "the loop writes dest[size] on a malloc(size) buffer.\n\nSOURCE:\n"
              + TARGET.read_text())
    sink.emit("stage", stage="repair", status="info", message="repair-shaped request")
    t0 = time.time()
    r = client.generate_patch("beta", prompt)
    dt = time.time() - t0
    result["repair"] = {
        "seconds": round(dt, 2), "tokens_in": r["tokens_in"], "tokens_out": r["tokens_out"],
        "tokens_per_s": round(r["tokens_out"] / dt, 1) if dt else None,
        "patch_extracted": bool(r["patch"] or r["replacement"]),
        "format": "whole-function" if r["replacement"] else ("diff" if r["patch"] else "none"),
    }
    sink.emit("stage", stage="repair", status="ok" if result["repair"]["patch_extracted"] else "fail",
              message=f"{result['repair']['tokens_per_s']} tok/s, patch extracted: "
                      f"{result['repair']['patch_extracted']}")

    sink.emit("stage", stage="critic", status="info", message="structured JSON-schema request")
    t0 = time.time()
    try:
        raw = client.structured_call(
            model=model, system_prompt=CRITIC_SYSTEM_PROMPT,
            user_content=("VULNERABILITY: off-by-one write.\nREJECTED PATCH: ```+ if (size > 1024) return;```\n"
                          "GATE: pov\nOUTPUT: AddressSanitizer: heap-buffer-overflow at line 8"),
            schema=CRITIC_SCHEMA, max_tokens=600)
        parsed = json.loads(raw)
        missing = [k for k in CRITIC_SCHEMA["schema"]["required"] if k not in parsed]
        result["structured"] = {"seconds": round(time.time() - t0, 2), "ok": not missing,
                                "missing_keys": missing}
    except Exception as e:
        result["structured"] = {"seconds": round(time.time() - t0, 2), "ok": False,
                                "error": f"{type(e).__name__}: {str(e)[:200]}"}
    sink.emit("stage", stage="critic", status="ok" if result["structured"]["ok"] else "fail",
              message="valid schema-conforming JSON" if result["structured"]["ok"]
              else result["structured"].get("error", "schema keys missing"))

    if is_local:
        # Measured while the model is loaded. The weights live in the Ollama
        # server, not in this process, and are asked of Ollama (not `ps`).
        result["model_server_mb"] = ollama_memory_mb()
    result["ok"] = result["repair"]["patch_extracted"] and result["structured"]["ok"]
    _write(result)
    sink.emit("run_done", stage="run", status="ok" if result["ok"] else "fail",
              message="model check finished", **{"ok": result["ok"]})
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result["ok"] else 1


def _write(result: dict) -> None:
    out = PROJECT_ROOT / "reports" / "special" / "modelcheck.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
