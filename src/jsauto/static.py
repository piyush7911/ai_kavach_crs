"""
Static detection for a Node/Express application.

Runs Semgrep with VENDORED rule files only (config/semgrep/*.yaml): no registry access, so the
scan works with no network and uses exactly the rules that are in the repository.

Three things happen after Semgrep returns, and each is recorded rather than silent:

  * hits are merged: two rules flagging the same line for the same class are one finding;
  * hits that are not defects are SUPPRESSED, with the reason kept in the output (a bcrypt hash
    in a seed script is not a leaked secret; a six-attribute cookie warning is one defect);
  * each remaining hit is mapped to its enclosing JavaScript function with Tree-sitter, because
    the repair stage patches a function, not a line.
"""

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import tree_sitter_javascript
from tree_sitter import Language, Parser

from src.jsauto.findings import Finding

RULES_DIR = Path(__file__).resolve().parents[2] / "config" / "semgrep"

# Directories that are never application source.
EXCLUDES = ("node_modules", "vendor", "dist", "build", "coverage", "*.min.js", ".git")
# Test directories are never scanned: Semgrep's built-in ignore list already skips test/ and tests/,
# and a defect in a test file is not a defect in the application.
TEST_DIRS = ("test", "tests", "__tests__", "spec", "cypress")

# Vendored rule id (last dotted component) -> kavach class, for rules without metadata.
_CLASS_BY_RULE = {
    "code-string-concat": "eval-injection",
    "express-open-redirect": "open-redirect",
    "detected-private-key": "private-key-in-repo",
}
_COOKIE_RULE = re.compile(r"^express-cookie-session-")

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

_FUNCTION_NODES = {
    "function_declaration", "generator_function_declaration", "function_expression",
    "function", "arrow_function", "method_definition",
}


def semgrep_binary() -> str:
    local = Path(sys.executable).parent / "semgrep"
    if local.exists():
        return str(local)
    from shutil import which
    found = which("semgrep")
    if not found:
        raise RuntimeError("semgrep is not installed (pip install semgrep)")
    return found


# -- enclosing function ----------------------------------------------------------------------------

_PARSER: Optional[Parser] = None


def _parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        _PARSER = Parser(Language(tree_sitter_javascript.language()))
    return _PARSER


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _function_name(node, src: bytes) -> str:
    """Best name for a function node: its own, else what it is assigned to, else a placeholder."""
    own = node.child_by_field_name("name")
    if own is not None:
        return _text(own, src)
    parent = node.parent
    if parent is None:
        return ""
    if parent.type == "variable_declarator":
        n = parent.child_by_field_name("name")
        return _text(n, src) if n is not None else ""
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None:
            if left.type == "member_expression":                 # this.displayX = (req, res) => ...
                prop = left.child_by_field_name("property")
                return _text(prop, src) if prop is not None else _text(left, src)
            return _text(left, src)
    if parent.type == "pair":
        key = parent.child_by_field_name("key")
        return _text(key, src) if key is not None else ""
    return ""


def enclosing_function(source: bytes, line: int) -> tuple[str, int, int]:
    """(name, start_line, end_line) of the innermost NAMED function covering `line` (1-based)."""
    tree = _parser().parse(source)
    best = ("", 0, 0)
    stack = [tree.root_node]
    row = line - 1
    while stack:
        node = stack.pop()
        if node.start_point[0] > row or node.end_point[0] < row:
            continue
        if node.type in _FUNCTION_NODES:
            name = _function_name(node, source)
            if name and (best[1] == 0 or node.start_point[0] >= best[1] - 1):
                best = (name, node.start_point[0] + 1, node.end_point[0] + 1)
        stack.extend(node.children)
    return best


# -- scan ---------------------------------------------------------------------------------------------

def _run_semgrep(root: Path) -> dict:
    configs = sorted(RULES_DIR.glob("*.yaml"))
    if not configs:
        raise RuntimeError(f"no vendored rules found in {RULES_DIR}")
    cmd = [semgrep_binary(), "--metrics=off", "--disable-version-check", "--quiet", "--json"]
    for c in configs:
        cmd += ["--config", str(c)]
    for pattern in EXCLUDES + TEST_DIRS:
        cmd += ["--exclude", pattern]
    cmd.append(".")
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=600)
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise RuntimeError("semgrep produced no JSON: " + (proc.stderr or proc.stdout)[:300])


def _classify(result: dict) -> tuple[str, str]:
    rule = result["check_id"].split(".")[-1]
    meta = result.get("extra", {}).get("metadata", {}) or {}
    if meta.get("kavach_class"):
        return meta["kavach_class"], rule
    if _COOKIE_RULE.match(rule):
        return "insecure-session-cookie", rule
    return _CLASS_BY_RULE.get(rule, rule), rule


def _suppression(klass: str, result: dict, text: str) -> str:
    """A reason this hit is not a defect, or ''."""
    rule = result["check_id"].split(".")[-1]
    if rule == "detected-bcrypt-hash":
        return "a bcrypt hash is a stored credential digest in seed data, not a leaked secret"
    return ""


def _merge_by_scope(findings: list[Finding]) -> list[Finding]:
    """
    One defect, one finding. Three `eval()` calls in one handler are one repair task, and so are
    several secrets in one seed file; the lines are kept in evidence so nothing is lost.
    """
    out: dict[tuple, Finding] = {}
    for f in findings:
        if f.klass == "hardcoded-secret":
            key = (f.file, "", f.klass)
        elif f.function:
            key = (f.file, f.function, f.klass)
        else:
            key = (f.file, f.line, f.klass)
        if key not in out:
            f.evidence["lines"] = [f.line]
            out[key] = f
            continue
        keep = out[key]
        keep.evidence["lines"] = sorted(set(keep.evidence["lines"]) | {f.line})
        keep.evidence["rules"] = sorted(set(keep.evidence["rules"]) | set(f.evidence["rules"]))
        keep.line, keep.end_line = min(keep.line, f.line), max(keep.end_line, f.end_line)
    return list(out.values())


def scan(root: Path) -> dict:
    """
    Returns {"findings": [Finding], "suppressed": [Finding], "files_scanned": n, "semgrep_errors": [...]}.
    """
    root = Path(root).resolve()
    raw = _run_semgrep(root)
    merged: dict[tuple, Finding] = {}
    suppressed: list[Finding] = []
    sources: dict[str, bytes] = {}

    for r in sorted(raw.get("results", []), key=lambda x: (x["path"], x["start"]["line"])):
        rel = Path(r["path"]).as_posix()
        klass, rule = _classify(r)
        why = _suppression(klass, r, "")
        meta = r.get("extra", {}).get("metadata", {}) or {}
        line = r["start"]["line"]
        f = Finding(
            id="", source="semgrep", klass=klass, file=rel, line=line, end_line=r["end"]["line"],
            rule=rule, cwe=(meta.get("cwe") or "") if isinstance(meta.get("cwe"), str) else
            (meta.get("cwe") or [""])[0].split(":")[0],
            owasp=meta.get("owasp") if isinstance(meta.get("owasp"), str) else "",
            severity=_SEVERITY.get(r["extra"].get("severity", "WARNING"), "medium"),
            confidence=str(meta.get("confidence", "medium")).lower(),
            message=(r["extra"].get("message") or "").strip().split("\n")[0][:240],
            evidence={"rules": [rule]},
        )
        if why:
            f.status, f.reason = "suppressed", why
            suppressed.append(f)
            continue
        # one defect per (file, line-or-region, class); the cookie warnings all point at one call
        key = (rel, line if klass != "insecure-session-cookie" else 0, klass)
        if key in merged:
            merged[key].evidence["rules"].append(rule)
            merged[key].confidence = max(merged[key].confidence, f.confidence,
                                         key=["low", "medium", "high"].index) \
                if f.confidence in ("low", "medium", "high") else merged[key].confidence
            continue
        merged[key] = f

    findings = list(merged.values())
    for f in findings:
        path = root / f.file
        if path.suffix in (".js", ".mjs", ".cjs", ".ts"):
            src = sources.setdefault(f.file, path.read_bytes())
            name, start, end = enclosing_function(src, f.line)
            f.function = name
            if name:
                f.evidence["function_lines"] = [start, end]
        f.evidence["rules"] = sorted(set(f.evidence["rules"]))
    findings = _merge_by_scope(findings)
    findings.sort(key=lambda f: (f.file, f.line, f.klass))
    for i, f in enumerate(findings, 1):
        f.id = f"JS-{i:03d}"
    return {"findings": findings, "suppressed": suppressed,
            "semgrep_errors": [e.get("message", str(e))[:160] for e in raw.get("errors", [])]}
