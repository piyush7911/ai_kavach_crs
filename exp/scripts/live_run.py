"""Start an app, run the step-5 live checks against it, stop it.
    python -m exp.scripts.live_run nodegoat|vampi|vulnerableapp
NodeGoat: the project's own loopback AppServer (own port + throwaway Mongo DB). VAmPI: its Flask app from the exp/live venv on 127.0.0.1:5001.
VulnerableApp: expected already running on 127.0.0.1:9090 (./gradlew bootRun with the exp/third_party JDK 17)."""
import collections, json, socket, subprocess, sys, time
from pathlib import Path
import urllib.request
from exp.scripts import live_checks as lc

ROOT = Path(".").resolve()
def wait_port(port, t=40):
    for _ in range(t * 2):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0: return True
        time.sleep(0.5)
    return False

def go(base, routes, out, ctx="", seed="", budget=1500, creds=None):
    L = lc.Live(base, ctx, budget); L.creds = creds or []
    if seed: L.req("GET", L.base + seed)
    rts = json.load(open(routes))["routes"]; t = time.time(); lc.run(L, rts)
    reach = sum(1 for b in L.baselines.values() if b.get("status") not in (None, 404, 405))
    json.dump({"base": base, "requests": L.n, "seconds": round(time.time() - t, 1), "routes": len(rts), "reachable": reach, "findings": L.findings, "baselines": L.baselines}, open(out, "w"), indent=1)
    print(base, len(rts), "routes,", reach, "reachable,", L.n, "requests,", dict(collections.Counter(f["class"] for f in L.findings)))

if __name__ == "__main__":
    which = sys.argv[1]; Path("exp/results/live").mkdir(parents=True, exist_ok=True)
    if which == "nodegoat":
        from benchmarks.nodegoat.appserver import AppServer
        with AppServer(tree=ROOT / "benchmark_workspace/NodeGoat") as app:
            go(app.base_url, "exp/knowledge/routes_NodeGoat.json", "exp/results/live/NodeGoat.live.json")
    elif which == "vampi":
        py = "/private/tmp/claude-501/jr/exp/live/venv_vampi/bin/python"
        p = subprocess.Popen([py, "-c", "from config import vuln_app; vuln_app.run(host='127.0.0.1', port=5001, debug=False)"], cwd=ROOT / "benchmark_workspace/VAmPI",
                             stdout=open("exp/live/logs/vampi.log", "w"), stderr=subprocess.STDOUT)
        try:
            assert wait_port(5001), "VAmPI did not start; see exp/live/logs/vampi.log"
            go("http://127.0.0.1:5001", "exp/knowledge/routes_VAmPI.json", "exp/results/live/VAmPI.live.json", seed="/createdb", creds=["name1", "pass1"])   # seeded test user, as a deployment would supply
        finally:
            p.terminate()
    elif which == "vulnerableapp":
        go("http://127.0.0.1:9090", "exp/knowledge/routes_VulnerableApp.json", "exp/results/live/VulnerableApp.live.json", ctx="/VulnerableApp", budget=4000)
