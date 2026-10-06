"""Deterministic template-based patching (Phase 1 MVP). No LLM.

For narrow, well-understood classes the fix is a fixed mechanical edit, not a generation task (TBar/TemVUR).
This applies such templates by matching the vulnerable literal and rewriting it, on a SCRATCH COPY (the
target is never modified in place), then re-verifies the weak literal is gone. Classes with no safe template
fall through to the LLM repair loop (unchanged). Dependencies are REPORT-ONLY — never version-bumped.

Phase 1 covers the pure literal swaps that cannot change behaviour beyond the security property:
  - weak-hash:   getInstance("MD5"|"SHA-1") -> "SHA-256"; python hashlib.md5(/sha1( -> hashlib.sha256(
  - cookie-flags: setSecure(false)/setHttpOnly(false) -> (true)
Phase 2 (not here): weak-cipher mode swap (ECB->GCM needs an IV, so not a pure literal), SQLi->parameterized,
XSS->escaper, and inserting a missing cookie flag. Those need a real AST rewrite and go through the gate.

    python -m exp.scripts.patch_templates --self-check
    python -m exp.scripts.patch_templates <file> <class> [--out scratchdir]
"""
from __future__ import annotations

import argparse
import difflib
import re
from pathlib import Path

# a vulnerable dependency / CVE is advisory-only: we name the fixed version but NEVER edit a manifest or
# bump a version (air-gapped finale can't re-resolve/test; a bump can break the app). Hard refusal.
DEPENDENCY_CLASSES = {"vulnerable-dependency", "dependency", "sca", "cve", "known-vulnerable-dependency"}

# each template: (class, applies-to suffixes, compiled pattern, replacement, one-line description)
_T = [
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


def apply_templates(klass: str, filename: str, src: str) -> tuple[str, bool, str]:
    """Return (patched_src, applied, note). Deterministic; no model. Dependencies are refused."""
    if klass in DEPENDENCY_CLASSES:
        return src, False, "advisory-only: dependency findings are reported, never version-bumped"
    suffix = Path(filename).suffix
    out, applied, notes = src, False, []
    for cls, suffixes, pat, repl, desc in _T:
        if cls != klass or suffix not in suffixes:
            continue
        new, n = pat.subn(repl, out)
        if n:
            out, applied = new, True
            notes.append(f"{desc} x{n}")
    return out, applied, ("; ".join(notes) if applied else "no template matched")


def verify_clean(klass: str, filename: str, patched: str) -> bool:
    """Re-check the weak literal is gone from the patched source (the template's own detector)."""
    for cls, suffixes, pat, _repl, _desc in _T:
        if cls == klass and Path(filename).suffix in suffixes and pat.search(patched):
            return False
    return True


def patch_file(path: str, klass: str, out_dir: str) -> dict:
    """Apply templates to a file on a scratch copy; return a result dict with the diff. Never touches `path`."""
    p = Path(path)
    src = p.read_text(errors="replace")
    patched, applied, note = apply_templates(klass, p.name, src)
    res = {"file": path, "class": klass, "applied": applied, "note": note,
           "verified_clean": applied and verify_clean(klass, p.name, patched)}
    if applied:
        out = Path(out_dir) / p.name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(patched)
        res["patched_copy"] = str(out)
        res["diff"] = "".join(difflib.unified_diff(src.splitlines(True), patched.splitlines(True),
                                                    f"a/{p.name}", f"b/{p.name}"))
    return res


def _self_check():
    # weak-hash Java
    j = 'MessageDigest md = MessageDigest.getInstance("MD5");'
    out, ok, _ = apply_templates("weak-hash", "X.java", j)
    assert ok and 'getInstance("SHA-256")' in out and "MD5" not in out, out
    assert verify_clean("weak-hash", "X.java", out)
    # weak-hash Python
    out, ok, _ = apply_templates("weak-hash", "x.py", "h = hashlib.md5(data).hexdigest()")
    assert ok and "hashlib.sha256(" in out, out
    # cookie flags
    out, ok, _ = apply_templates("cookie-flags", "C.java", "c.setSecure(false); c.setHttpOnly( false );")
    assert ok and "setSecure(true)" in out and "setHttpOnly( true )" in out, out
    # dependency class is refused (report-only)
    out, ok, note = apply_templates("vulnerable-dependency", "pom.xml", "<version>1.0</version>")
    assert not ok and out == "<version>1.0</version>" and "advisory-only" in note
    # a class with no template falls through untouched
    out, ok, _ = apply_templates("business-logic", "A.java", "x")
    assert not ok and out == "x"
    # a safe hash is not touched (no false edit)
    out, ok, _ = apply_templates("weak-hash", "X.java", 'getInstance("SHA-256")')
    assert not ok and out == 'getInstance("SHA-256")'
    print("patch_templates self-check: OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("klass", nargs="?")
    ap.add_argument("--out", default="exp/results/patched")
    ap.add_argument("--self-check", action="store_true")
    a = ap.parse_args()
    if a.self_check or not a.file:
        _self_check()
    else:
        import json
        print(json.dumps(patch_file(a.file, a.klass, a.out), indent=1))
