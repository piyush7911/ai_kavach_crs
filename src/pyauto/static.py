"""Python static detection for AI Kavach — the Python counterpart of src/jsauto's detector.

Runs the generic Kavach Python rules (config/semgrep/kavach_py.yaml) with Semgrep, offline (local
rule file, no registry), and maps each hit to its enclosing Python function with tree-sitter-python.
Emits the SAME language-neutral `Finding` type the JS backend uses, so the rest of the system
(scoring, the runner's HTTP oracles, reporting) is unchanged. This proves the architecture is a
shared core with per-language front-ends: only the rules and the parser are language-specific here.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import tree_sitter_python
from tree_sitter import Language, Parser

from src.jsauto.findings import Finding

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "config" / "semgrep" / "kavach_py.yaml"
_PY = Language(tree_sitter_python.language())


def _parser() -> Parser:
    return Parser(_PY)


def _enclosing_function(source: bytes, line: int) -> tuple[str, int, int]:
    """(name, start_line, end_line) of the function that contains 1-indexed `line`, or ("",0,0)."""
    tree = _parser().parse(source)
    want = line - 1
    best = None
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition" and n.start_point[0] <= want <= n.end_point[0]:
            if best is None or n.start_point[0] > best.start_point[0]:
                best = n  # the innermost enclosing def
        stack.extend(n.children)
    if best is None:
        return "", 0, 0
    name_node = best.child_by_field_name("name")
    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace") if name_node else ""
    return name, best.start_point[0] + 1, best.end_point[0] + 1


# Directories that are never application source: dependency/build/vendor trees, never the target's own code.
EXCLUDES = ("node_modules", "vendor", "dist", "build", ".git", ".venv", "venv", "env", ".env",
            "site-packages", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".eggs")


def scan(target: str | Path, rules: Path = RULES) -> list[Finding]:
    target = Path(target)
    cmd = ["semgrep", "--config", str(rules), str(target), "--quiet", "--json",
           "--metrics", "off", "--disable-version-check"]
    for pattern in EXCLUDES:
        cmd += ["--exclude", pattern]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode not in (0, 1):   # 1 = findings present; anything else is a real failure
        raise RuntimeError(f"semgrep failed (rc={r.returncode}): {r.stderr[-400:]}")
    data = json.loads(r.stdout or "{}")
    findings, src_cache = [], {}
    for i, res in enumerate(data.get("results", []), 1):
        path = Path(res["path"])
        meta = res.get("extra", {}).get("metadata", {})
        line = res["start"]["line"]
        if path not in src_cache:
            try:
                src_cache[path] = path.read_bytes()
            except OSError:
                src_cache[path] = b""
        fn, fstart, fend = _enclosing_function(src_cache[path], line)
        rel = path.relative_to(target) if target in path.parents or path == target else path
        findings.append(Finding(
            id=f"PY-{i:03d}", source="semgrep",
            klass=meta.get("kavach_class", res["check_id"].split(".")[-1]),
            file=str(rel).replace("\\", "/"), line=line, end_line=res["end"]["line"],
            function=fn, rule=res["check_id"].split(".")[-1], cwe=meta.get("cwe", ""),
            owasp=meta.get("owasp", ""), severity=str(res.get("extra", {}).get("severity", "medium")).lower(),
            confidence=meta.get("confidence", "medium"),
            message=res.get("extra", {}).get("message", ""),
            evidence={"function_lines": [fstart, fend], "lines": [line]}))
    return findings
