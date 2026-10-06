"""T6: content-addressed cache for expensive static analysis, so sprint re-runs don't re-scan.

During a 6h tuning sprint the same target is scanned over and over. The slow steps (Opengrep corpus, static
taint) are pure functions of the source tree, so we fingerprint the tree (sorted path+size+mtime, hashed)
and cache the step's findings under that fingerprint. Unchanged tree => instant reuse; any file change =>
the fingerprint changes => a fresh scan (safe: never serves a stale result for changed code). Findings
round-trip through Finding.to_dict / Finding(**d). Whole-tree granularity now; per-file incremental (re-scan
only changed files against a cached base, CodeQL/Semgrep-style) is the future upgrade.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.jsauto.findings import Finding

_CACHE_DIR = Path(".kavach_cache")
_EXTS = (".py", ".java", ".js", ".ts", ".kt", ".go", ".rb", ".php", ".cs")
_SKIP = ("node_modules", "/.git/", "/build/", "/target/", "/.kavach_cache/", "/dist/")


def tree_fingerprint(target: str | Path) -> str:
    """A fast fingerprint of the source tree: sha256 over sorted (relpath, size, mtime_ns)."""
    root = Path(target)
    h = hashlib.sha256()
    for f in sorted(root.rglob("*")):
        if f.suffix not in _EXTS or any(s in "/" + str(f).replace("\\", "/") for s in _SKIP):
            continue
        try:
            st = f.stat()
        except OSError:
            continue
        h.update(f"{f.relative_to(root)}:{st.st_size}:{st.st_mtime_ns}\n".encode())
    return h.hexdigest()[:16]


def _path(target, step, extra):
    key = hashlib.sha256(f"{step}|{extra}|{tree_fingerprint(target)}".encode()).hexdigest()[:20]
    return _CACHE_DIR / f"{step}_{key}.json"


def load(target, step: str, extra: str = ""):
    """Return cached findings for (tree, step, extra), or None on miss."""
    p = _path(target, step, extra)
    if not p.exists():
        return None
    try:
        return [Finding(**d) for d in json.loads(p.read_text())]
    except (ValueError, TypeError, OSError):
        return None


def save(target, step: str, findings, extra: str = "") -> None:
    """Cache a step's findings under the current tree fingerprint."""
    try:
        _CACHE_DIR.mkdir(exist_ok=True)
        _path(target, step, extra).write_text(
            json.dumps([f.to_dict() if hasattr(f, "to_dict") else f for f in findings], default=str))
    except OSError:
        pass
