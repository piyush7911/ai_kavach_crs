"""Spec-free autonomous discovery on VAmPI — NO OpenAPI spec read.

Same oracle families as benchmarks.pyprobe_vampi, but the routes come from the LIVE app's url_map
instead of a spec file. This is the realistic finale case: handed an app with no spec, introspect its
routes (method, path, path params, and the exact handler for repair), infer what the url_map omits
(auth, credential-route bodies) dynamically, then probe. Route introspection runs in the app's own
interpreter (here the py3.11 venv VAmPI needs); probing is over HTTP, so it is interpreter-agnostic.

    python -m benchmarks.pyprobe_nospec_vampi
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from benchmarks.crosslang_vampi import VAMPI_AUTH
from src.pyauto.probes import ProbeCtx, Route, enrich_routes, probe

BASE = "http://127.0.0.1:5001"
TREE = Path("benchmark_workspace/VAmPI")
PYBIN = "/tmp/vampi311/bin/python"
REPO = Path(__file__).resolve().parents[1]

# Run inside the app's interpreter: import the app object, read its routes via routes_from_wsgi, emit JSON.
_DUMP = (
    "import os,sys,json; sys.path.append(os.environ['REPO']);"  # cwd (the app) wins; REPO only adds our pkg
    "os.environ.setdefault('vulnerable','1');"
    "import config; from src.pyauto.probes import routes_from_wsgi;"
    "from dataclasses import asdict;"
    "print(json.dumps([asdict(r) for r in routes_from_wsgi(config.vuln_app)]))"
)


def _seed():
    for attempt in range(4):
        try:
            urllib.request.urlopen(BASE + "/createdb", timeout=10).read()
            return
        except Exception:  # noqa: BLE001
            if attempt == 3:
                raise
            time.sleep(0.5)


def _discover_routes() -> list[Route]:
    out = subprocess.run([PYBIN, "-c", _DUMP], cwd=TREE, env={"REPO": str(REPO), "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"route introspection failed:\n{out.stderr[-800:]}")
    return [Route(**d) for d in json.loads(out.stdout)]


def main() -> int:
    try:
        _seed()
    except Exception as e:  # noqa: BLE001
        print(f"VAmPI not reachable at {BASE} — start it. {e}")
        return 2
    routes = _discover_routes()
    print(f"{len(routes)} routes from the live url_map (no spec); inferring auth + bodies ...")
    ctx = ProbeCtx(base_url=BASE, auth=VAMPI_AUTH, reseed=_seed)
    enrich_routes(routes, ctx)
    _seed()
    findings = probe(routes, ctx)
    for f in findings:
        print(f"  CONFIRMED  {f.klass:26} {f.evidence['route']:28} -> {f.file}:{f.function or '-'}")
    print(f"\nautonomously discovered (spec-free): {len(findings)} bugs")
    return 0 if findings else 1


if __name__ == "__main__":
    sys.exit(main())
