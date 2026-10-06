"""Autonomous DISCOVERY on VAmPI: route-driven dynamic probes, no app-specific paths.

Reads VAmPI's OpenAPI spec for routes, then runs the generic oracle families over them and prints the
confirmed findings. Nothing here names a VAmPI endpoint — point `SPEC` at another app's spec (or feed
a Flask url_map) and the same probes run. Verification carries over; this closes the discovery gap.

Setup (same container as benchmarks/crosslang_vampi.py):
    docker run -d --name vampi -p 127.0.0.1:5001:5000 -e vulnerable=1 vampi:local
Run:  python -m benchmarks.pyprobe_vampi
"""
import sys
import urllib.request

from benchmarks.crosslang_vampi import VAMPI_AUTH
from src.pyauto.probes import ProbeCtx, probe, routes_from_openapi

BASE = "http://127.0.0.1:5001"
SPEC = "benchmark_workspace/VAmPI/openapi_specs/openapi3.yml"


def _seed():
    # /createdb intermittently 500s under back-to-back probes (SQLite lock); a short retry rides it out
    import time
    for attempt in range(4):
        try:
            urllib.request.urlopen(BASE + "/createdb", timeout=10).read()
            return
        except Exception:  # noqa: BLE001
            if attempt == 3:
                raise
            time.sleep(0.5)


def main() -> int:
    try:
        _seed()
    except Exception as e:  # noqa: BLE001
        print(f"VAmPI not reachable at {BASE} — start it (see header). {e}")
        return 2
    routes = routes_from_openapi(SPEC)
    print(f"{len(routes)} routes from {SPEC}; probing ...")
    ctx = ProbeCtx(base_url=BASE, auth=VAMPI_AUTH, reseed=_seed)
    findings = probe(routes, ctx)
    for f in findings:
        print(f"  CONFIRMED  {f.klass:26} {f.evidence['route']:28}  ::  {f.reason[:70]}")
    print(f"\nautonomously discovered + confirmed: {len(findings)} bugs")
    return 0 if findings else 1


if __name__ == "__main__":
    sys.exit(main())
