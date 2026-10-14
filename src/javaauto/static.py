"""Java static detection for AI Kavach — the Java counterpart of src/pyauto/static.py.

Runs the generic Kavach Java rules (config/semgrep/kavach_java.yaml) with Semgrep, offline (local rule
file, no registry), and maps each hit to its enclosing Java method with tree-sitter-java. Emits the SAME
language-neutral `Finding` the other backends use, so scoring, the HTTP oracles and reporting are
unchanged — a third front-end on the shared core, only the rules and the parser are Java-specific.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Parser

from src.jsauto.findings import Finding

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "config" / "semgrep" / "kavach_java.yaml"
_JAVA = Language(tree_sitter_java.language())
_METHOD_NODES = ("method_declaration", "constructor_declaration")


def _parser() -> Parser:
    return Parser(_JAVA)


def _enclosing_function(source: bytes, line: int) -> tuple[str, int, int]:
    """(name, start_line, end_line) of the method that contains 1-indexed `line`, or ("",0,0)."""
    tree = _parser().parse(source)
    want = line - 1
    best = None
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in _METHOD_NODES and n.start_point[0] <= want <= n.end_point[0]:
            if best is None or n.start_point[0] > best.start_point[0]:
                best = n  # innermost enclosing method
        stack.extend(n.children)
    if best is None:
        return "", 0, 0
    name_node = best.child_by_field_name("name")
    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace") if name_node else ""
    return name, best.start_point[0] + 1, best.end_point[0] + 1


# Directories that are never application source: dependency/build trees, never the target's own code.
EXCLUDES = ("node_modules", "vendor", "dist", "build", "target", ".git", ".venv", "venv",
            "site-packages", "__pycache__", ".gradle", ".m2")


def scan(target: str | Path, rules: Path = RULES) -> list[Finding]:
    target = Path(target)
    cmd = ["semgrep", "--config", str(rules), str(target), "--quiet", "--json",
           "--metrics", "off", "--disable-version-check", "--no-git-ignore"]
    for pattern in EXCLUDES:
        cmd += ["--exclude", pattern]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    if r.returncode not in (0, 1):
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
            id=f"JAVA-{i:03d}", source="semgrep",
            klass=meta.get("kavach_class", res["check_id"].split(".")[-1]),
            file=str(rel).replace("\\", "/"), line=line, end_line=res["end"]["line"],
            function=fn, rule=res["check_id"].split(".")[-1], cwe=meta.get("cwe", ""),
            owasp=meta.get("owasp", ""), severity=str(res.get("extra", {}).get("severity", "medium")).lower(),
            confidence=meta.get("confidence", "medium"),
            message=res.get("extra", {}).get("message", ""),
            evidence={"function_lines": [fstart, fend], "lines": [line]}))
    return findings
