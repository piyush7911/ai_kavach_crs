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
CORPUS = ROOT / "exp" / "third_party" / "opengrep-rules"   # vendored community rules (~890, Commons Clause)
_PARAM = re.compile(r"""\.get\(\s*['"]([^'"]+)['"]|getParameter\(\s*['"]([^'"]+)['"]|\[\s*['"]([^'"]+)['"]\s*\]""")

# map a community rule's id/CWE to one of OUR oracle classes (so breadth hits join the confirm/report path);
# unrecognised rules keep their own id as the class (still a useful candidate).
_CWE_CLASS = {"89": "sql-injection", "943": "nosql-injection", "78": "command-injection",
              "77": "command-injection", "79": "xss", "22": "path-traversal", "918": "ssrf",
              "601": "open-redirect", "611": "xxe", "502": "insecure-deserialization"}
_ID_HINTS = [("sqli", "sql-injection"), ("sql", "sql-injection"), ("xss", "xss"), ("html-string", "xss"),
             ("ssrf", "ssrf"), ("url-host", "ssrf"), ("path", "path-traversal"), ("traversal", "path-traversal"),
             ("command", "command-injection"), ("redirect", "open-redirect"), ("xxe", "xxe"),
             ("doctype", "xxe"), ("deserial", "insecure-deserialization")]


def _normalize_class(check_id: str, cwe: str) -> str:
    num = str(cwe).upper().replace("CWE-", "").strip()
    if num in _CWE_CLASS:
        return _CWE_CLASS[num]
    low = check_id.lower()
    for kw, cls in _ID_HINTS:
        if kw in low:
            return cls
    return check_id.split(".")[-1]


def _binary() -> str | None:
    return shutil.which("opengrep") or shutil.which("semgrep")   # opengrep preferred; semgrep is a fallback


def _source_param(res: dict) -> str:
    """The attacker-controlled parameter name, from the taint dataflow source (e.g. request.args.get('id'))."""
    trace = res.get("extra", {}).get("dataflow_trace", {}) or {}
    src = (trace.get("taint_source") or trace.get("intermediate_vars") or [])
    text = json.dumps(src) + json.dumps(res.get("extra", {}).get("lines", ""))
    m = _PARAM.search(text)
    return next((g for g in m.groups() if g), "") if m else ""


_LANG_DIR = {".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript",
             ".ts": "typescript", ".tsx": "typescript", ".php": "php", ".go": "go", ".rb": "ruby"}


def _rule_configs(rules: Path, target: Path) -> list[str]:
    """For the community corpus (a dir of per-language rule folders), pick only the language folders the
    target actually uses — the whole corpus has rules that fail to parse and abort the run. Otherwise use
    the given rules path as-is."""
    if rules.is_dir() and any((rules / d).is_dir() for d in set(_LANG_DIR.values())):
        exts = {p.suffix for p in target.rglob("*") if p.suffix in _LANG_DIR} if target.is_dir() else {target.suffix}
        subs = sorted({str(rules / _LANG_DIR[e]) for e in exts if (rules / _LANG_DIR[e]).is_dir()})
        return subs or [str(rules)]
    return [str(rules)]


def findings_from_opengrep(target: str | Path, rules: Path = None, binary: str = None) -> list[Finding]:
    """Run a rule set over a source tree with Opengrep; return candidate Findings. Defaults to the big
    vendored community corpus (more rules = more classes detected) when present, else our clean-license
    taint rules. Hits are candidates — our oracle/triage decides precision."""
    rules = rules or (CORPUS if CORPUS.exists() else TAINT_RULES)
    binary = binary or _binary()
    if not binary:
        return []
    target = Path(target)
    configs = _rule_configs(Path(rules), target)        # language-matched subdirs for the corpus
    cmd = [binary, "scan", "--quiet", "--json", "--no-git-ignore"]
    for c in configs:
        cmd += ["--config", c]
    # Dependency/vendor trees are never application source; scanning them produces findings inside
    # libraries we didn't write and can't fix, which is exactly the false-positive risk we can't afford.
    for pattern in ("node_modules", "vendor", "dist", "build", ".git", ".venv", "venv", "env",
                    "site-packages", "__pycache__", ".tox"):
        cmd += ["--exclude", pattern]
    cmd.append(str(target))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:                                                # opengrep may exit non-zero on partial rule errors
        data = json.loads(r.stdout or "{}")             # but still emit valid results — trust the JSON
    except ValueError:
        return []
    out = []
    for i, res in enumerate(data.get("results", []), 1):
        meta = res.get("extra", {}).get("metadata", {})
        path = Path(res["path"])
        rel = path.relative_to(target) if target in path.parents or path == target else path
        out.append(Finding(
            id=f"OG-{i:03d}", source="opengrep", status="candidate", confidence="medium",
            klass=meta.get("kavach_class") or _normalize_class(res["check_id"], meta.get("cwe", "")),
            file=str(rel).replace("\\", "/"), line=res["start"]["line"], end_line=res["end"]["line"],
            rule=res["check_id"].split(".")[-1], cwe=meta.get("cwe", ""),
            message=res.get("extra", {}).get("message", ""),
            evidence={"param": _source_param(res), "lines": [res["start"]["line"]], "engine": Path(binary).name}))
    return out
