"""Opengrep (LGPL-2.1 Semgrep fork with inter-procedural taint) as a CANDIDATE source.

Why not just our Semgrep rules: a plain pattern flags every `.execute(...)`; a TAINT rule flags it only when
request input actually reaches it, cross-function — far fewer false alarms (piyush's benchmark: community
Java rules took recall 290→1248 but FPR to 0.42; taint keeps the recall with far less noise). These are
still CANDIDATES — our oracle confirms. Opengrep's JSON is the Semgrep schema, so parsing mirrors
src/pyauto/static.py; we also pull the tainted PARAM name out of the dataflow source so a hit can later be
confirmed over HTTP.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from src.jsauto.findings import Finding

ROOT = Path(__file__).resolve().parents[2]
TAINT_RULES = ROOT / "config" / "semgrep" / "kavach_taint.yaml"
_PARAM = re.compile(r"""\.get\(\s*['"]([^'"]+)['"]|getParameter\(\s*['"]([^'"]+)['"]|\[\s*['"]([^'"]+)['"]\s*\]""")


def _binary() -> str | None:
    return shutil.which("opengrep") or shutil.which("semgrep")   # opengrep preferred; semgrep is a fallback


def _source_param(res: dict) -> str:
    """The attacker-controlled parameter name, from the taint dataflow source (e.g. request.args.get('id'))."""
    trace = res.get("extra", {}).get("dataflow_trace", {}) or {}
    src = (trace.get("taint_source") or trace.get("intermediate_vars") or [])
    text = json.dumps(src) + json.dumps(res.get("extra", {}).get("lines", ""))
    m = _PARAM.search(text)
    return next((g for g in m.groups() if g), "") if m else ""


def findings_from_opengrep(target: str | Path, rules: Path = TAINT_RULES, binary: str = None) -> list[Finding]:
    """Run the taint ruleset over a source tree; return candidate Findings (status='candidate')."""
    binary = binary or _binary()
    if not binary:
        return []
    target = Path(target)
    cmd = [binary, "scan", "--quiet", "--json", "--config", str(rules), str(target)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode not in (0, 1):
        return []
    data = json.loads(r.stdout or "{}")
    out = []
    for i, res in enumerate(data.get("results", []), 1):
        meta = res.get("extra", {}).get("metadata", {})
        path = Path(res["path"])
        rel = path.relative_to(target) if target in path.parents or path == target else path
        out.append(Finding(
            id=f"OG-{i:03d}", source="opengrep", status="candidate", confidence="medium",
            klass=meta.get("kavach_class", res["check_id"].split(".")[-1]),
            file=str(rel).replace("\\", "/"), line=res["start"]["line"], end_line=res["end"]["line"],
            rule=res["check_id"].split(".")[-1], cwe=meta.get("cwe", ""),
            message=res.get("extra", {}).get("message", ""),
            evidence={"param": _source_param(res), "lines": [res["start"]["line"]], "engine": Path(binary).name}))
    return out
