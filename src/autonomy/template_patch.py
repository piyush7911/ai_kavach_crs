"""Deterministic template-based patching for the main pipeline (no LLM).

Template-first repair: for narrow, well-understood classes the fix is a fixed mechanical edit, not a
generation task. This produces the patch by matching the vulnerable literal and rewriting it, then
re-verifies the weak literal is gone. For the pure literal-swap classes here (weak-hash, cookie flags) the
edit cannot change behaviour beyond the security property and always compiles, so re-scan is the whole gate.
Classes with no safe template return None and the caller falls through to the LLM repair loop.

Hard rule: a vulnerable dependency / CVE is REPORT-ONLY. This engine refuses the dependency class family —
we name the fixed version elsewhere but never edit a manifest or bump a version (air-gapped: can't
re-resolve/test; a bump can break the app). Proven out in exp/ (BenchmarkJava: 64/64 patched + verified).
"""
from __future__ import annotations

import difflib
import re
from pathlib import Path

DEPENDENCY_CLASSES = {"vulnerable-dependency", "dependency", "sca", "cve", "known-vulnerable-dependency"}

# (class, file suffixes, pattern, replacement, description) — pure literal swaps only (Phase 1)
_TEMPLATES = [
    ("weak-hash", (".java",), re.compile(r'(getInstance\(\s*")(?:MD5|MD2|SHA-?1)(")'), r"\1SHA-256\2",
     'MessageDigest.getInstance("MD5"/"SHA-1") -> "SHA-256"'),
    ("weak-hash", (".py",), re.compile(r'\bhashlib\.(?:md5|sha1)\('), "hashlib.sha256(",
     "hashlib.md5(/sha1( -> hashlib.sha256("),
    ("cookie-flags", (".java",), re.compile(r'(\.setSecure\(\s*)false(\s*\))'), r"\1true\2",
     "setSecure(false) -> setSecure(true)"),
    ("cookie-flags", (".java",), re.compile(r'(\.setHttpOnly\(\s*)false(\s*\))'), r"\1true\2",
     "setHttpOnly(false) -> setHttpOnly(true)"),
    ("cookie-samesite", (".java",), re.compile(r'(\.setHttpOnly\(\s*)false(\s*\))'), r"\1true\2",
     "setHttpOnly(false) -> setHttpOnly(true)"),
]


def has_template(klass: str, filename: str = ".java") -> bool:
    suffix = Path(filename).suffix or filename
    return klass not in DEPENDENCY_CLASSES and any(c == klass and suffix in s for c, s, *_ in _TEMPLATES)


def apply_templates(klass: str, filename: str, src: str) -> tuple[str, bool, str]:
    """Return (patched_src, applied, note). Deterministic; dependencies refused (report-only)."""
    if klass in DEPENDENCY_CLASSES:
        return src, False, "advisory-only: dependency findings are reported, never version-bumped"
    suffix = Path(filename).suffix
    out, applied, notes = src, False, []
    for cls, suffixes, pat, repl, desc in _TEMPLATES:
        if cls != klass or suffix not in suffixes:
            continue
        new, n = pat.subn(repl, out)
        if n:
            out, applied = new, True
            notes.append(f"{desc} x{n}")
    return out, applied, ("; ".join(notes) if applied else "no template matched")


def _verify_clean(klass: str, filename: str, patched: str) -> bool:
    suffix = Path(filename).suffix
    for cls, suffixes, pat, *_ in _TEMPLATES:
        if cls == klass and suffix in suffixes and pat.search(patched):
            return False
    return True


def template_repair(finding: dict, tree: str | Path) -> dict | None:
    """Try a deterministic template fix for `finding` (needs file + class). Returns a result dict
    {status: 'proven'|'failed', class, file, note, diff} when a template applied, else None so the caller
    uses the LLM repair loop. Never modifies the target: the patch is produced and verified in memory; the
    unified diff is the deliverable (the pipeline reports it; applying is a separate, gated step)."""
    klass, rel = finding.get("klass") or finding.get("class"), finding.get("file")
    if not klass or not rel or rel in ("", "(runtime)"):
        return None
    path = Path(tree) / rel
    if not path.exists():
        return None
    src = path.read_text(errors="replace")
    patched, applied, note = apply_templates(klass, path.name, src)
    if not applied:
        return None
    clean = _verify_clean(klass, path.name, patched)
    diff = "".join(difflib.unified_diff(src.splitlines(True), patched.splitlines(True),
                                        f"a/{rel}", f"b/{rel}"))
    return {"status": "proven" if clean else "failed", "class": klass, "file": rel,
            "note": note + ("" if clean else " (weak literal still present after patch)"), "diff": diff}
