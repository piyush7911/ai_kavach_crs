"""End-to-end autonomous DISCOVER -> FIX -> PROVE on OWASP NodeGoat (Node.js), with a chosen model.

The JS counterpart of benchmarks.pyautofix_vampi. jsauto statically finds the bugs and builds a
replayable exploit per finding; the repair loop rewrites the one flagged function and the gate replays
the exploit (plus a regression suite and the exploit's VARIANTS for hardening) against a freshly-seeded
instance. A fix is accepted only when the exploit is gone, the golden flows still pass, and no variant
spelling slips through.

    export OPENAI_BASE_URL=... OPENAI_API_KEY=... MODEL=nvidia.nemotron-nano-3-30b
    python -m benchmarks.ngautofix
"""
import json
import os
import sys
from pathlib import Path

from openai import OpenAI

from benchmarks.nodegoat.appserver import AppServer
from benchmarks.nodegoat.exploit import Session, run_exploit
from benchmarks.nodegoat.runner import _check_flow, DEFAULT_FLOWS
from src.jsauto import probes, static
from src.jsauto.repair import FAIL, PASS, repair

ROOT = Path("benchmark_workspace/NodeGoat")
MODEL = os.environ.get("MODEL", "nvidia.nemotron-nano-3-30b")
_FLOWS = json.loads(DEFAULT_FLOWS.read_text())


class NodeGoatGates:
    """start() reboots a seeded instance so the current patch is what runs; replay()/regress() use it.
    _run_gates calls start -> replay -> regress (-> replay variants) per attempt, in that order."""
    def __init__(self):
        self._server = None

    def _stop(self):
        if self._server:
            self._server.stop()
            self._server = None

    def start(self, tree):
        self._stop()
        try:
            self._server = AppServer(Path(tree)).start()
            return PASS, "healthy"
        except Exception as e:  # noqa: BLE001
            return FAIL, f"app did not start: {e}"

    def replay(self, tree, exploit):          # PASS = the exploit no longer reproduces
        hit, detail = run_exploit(self._server.base_url, exploit)
        return (FAIL, detail) if hit else (PASS, detail)

    def regress(self, tree):
        for flow in _FLOWS:
            ok, detail = _check_flow(self._server.base_url, flow)
            if not ok:
                return FAIL, f"flow {flow.get('name', flow['path'])}: {detail}"
        return PASS, "golden flows pass"


class OpenAIModel:
    def __init__(self, client):
        self.client = client

    def complete(self, system, prompt, purpose="", max_tokens=0, model=None):
        r = self.client.chat.completions.create(
            model=model or MODEL, temperature=0, max_tokens=max_tokens or 1024,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""


def main() -> int:
    if not (ROOT / "server.js").exists():
        print(f"no NodeGoat at {ROOT}")
        return 2
    s = static.scan(ROOT)
    findings = s["findings"]
    for i, f in enumerate(findings, 1):
        f.id = f"JS-{i:03d}"
    probes.attach(findings)
    repairable = [f for f in findings if getattr(f, "exploit", None)]
    print(f"discovered {len(findings)} findings; {len(repairable)} with a replayable exploit; "
          f"fixing with {MODEL}\n")

    model = OpenAIModel(OpenAI(base_url=os.environ.get("OPENAI_BASE_URL"),
                               api_key=os.environ.get("OPENAI_API_KEY", "x")))
    gates = NodeGoatGates()
    proven = hardened = 0
    try:
        for f in repairable:
            variants = probes.variants_for(f.to_dict())
            print(f"-> {f.klass} in {f.file}:{f.function}  ({len(variants)} hardening variants)")
            out = repair(f.to_dict(), ROOT, model, gates, max_attempts=3, variants=variants)
            tag = out.status.upper() + (" + HARDENED" if out.hardened else "")
            print(f"   {tag} — {out.reason}")
            proven += out.status == "proven"
            hardened += out.hardened
    finally:
        gates._stop()
    print(f"\nautonomously fixed + proven: {proven} / {len(repairable)}  (hardened: {hardened})")
    return 0 if proven else 1


if __name__ == "__main__":
    sys.exit(main())
