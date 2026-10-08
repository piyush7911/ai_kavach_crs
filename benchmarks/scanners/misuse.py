"""API-misuse source scanner (deterministic, no Joern) as a candidate source for kavach.

A lightweight port of the misuse catalogue (exp/knowledge/misuse_catalog.json) restricted to the DIRECT,
literal sink calls that are false-positive-free: a `MessageDigest.getInstance("MD5")` literal IS weak, full
stop. It deliberately does NOT match `getProperty("alg","MD5")` default-literals (BenchmarkJava showed those
cause crypto false alarms — the real algorithm comes from a config file). So every hit here is a fact, safe
for the confirmed tier, and most are exactly what the template FIX stage patches (weak-hash/cipher/random,
cookie flags). Java + Python.
"""
from __future__ import annotations

import re
from pathlib import Path

from src.jsauto.findings import Finding

_EXTS = (".java", ".py", ".kt")
_SKIP = ("node_modules", "/test/", "/tests/", "/build/", "/.git/", "/target/",
         "/.venv/", "/venv/", "/env/", "/site-packages/", "/__pycache__/", "/.tox/")

# (class, cwe, compiled pattern) — direct, literal, FP-safe sink calls only
_RULES = [
    ("weak-hash", "CWE-328",
     re.compile(r'(?:MessageDigest|DigestUtils)\s*\.\s*getInstance\(\s*"(?:MD2|MD4|MD5|SHA-?1|SHA-?0)"'
                r'|\bDigestUtils\.(?:md2|md5|sha1|sha)(?:Hex|Digest|Base64)?\s*\('
                r'|\bhashlib\.(?:md5|sha1|md4)\s*\(')),
    ("weak-cipher", "CWE-327",
     re.compile(r'Cipher\s*\.\s*getInstance\(\s*"(?:(?:DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)'
                r'(?:/|")|[^"]*?/ECB/)')),
    ("weak-random", "CWE-338",
     re.compile(r'\bnew\s+java\.util\.Random\s*\(|\bnew\s+Random\s*\(|\bMath\s*\.\s*random\s*\(')),
    ("cookie-flags", "CWE-1004", re.compile(r'\.setSecure\(\s*false\s*\)|\.setHttpOnly\(\s*false\s*\)')),
]


def findings_from_misuse(target: str | Path) -> list[Finding]:
    """Scan a source tree for FP-safe API-misuse literals; return confirmed Findings (the literal presence
    is the proof). Most are patchable by the template FIX stage."""
    root = Path(target)
    out, i = [], 0
    for f in root.rglob("*"):
        if f.suffix not in _EXTS or any(s in "/" + str(f).replace("\\", "/") for s in _SKIP):
            continue
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        rel = str(f.relative_to(root)).replace("\\", "/")
        for ln, text in enumerate(lines, 1):
            if text.lstrip().startswith(("//", "#", "*")):          # skip comments — not a real call site
                continue
            for klass, cwe, pat in _RULES:
                if pat.search(text):
                    i += 1
                    out.append(Finding(
                        id=f"MISUSE-{i:03d}", source="misuse", status="confirmed", confidence="high",
                        klass=klass, file=rel, line=ln, cwe=cwe, rule="misuse-literal",
                        message=f"{klass}: {text.strip()[:80]}",
                        reason=f"direct {klass} literal at {rel}:{ln}",
                        evidence={"location": f"{rel}:{ln}", "line_text": text.strip()[:120]}))
    return out
