"""
Start the live dashboard:

    python -m dashboard                      # http://127.0.0.1:8000
    python -m dashboard --port 9000
    python -m dashboard --host 0.0.0.0       # reachable on the network; set KAVACH_DASH_TOKEN first
"""

import argparse
import os
import sys

import uvicorn


def main() -> int:
    ap = argparse.ArgumentParser(description="AI Kavach live dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost") and not os.getenv("KAVACH_DASH_TOKEN"):
        print("Refusing to bind a network interface without KAVACH_DASH_TOKEN set.\n"
              "The dashboard can start jobs and accept uploads; set a token first:\n"
              "    export KAVACH_DASH_TOKEN=<something-long>   then open /?token=<it>",
              file=sys.stderr)
        return 2

    uvicorn.run("dashboard.app:app", host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
