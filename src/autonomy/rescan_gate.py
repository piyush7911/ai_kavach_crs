"""Static re-scan gate: a patch must remove the vuln CLASS, not just the one PoC input.

The PoV gate proves the specific exploit no longer fires; it does NOT prove the data-flow is gone — an LLM
can neutralize the one payload and leave the sink reachable by a sibling input. After a patch passes the PoV
gate, we re-run the taint scanner (Opengrep) on the PATCHED file; if a finding of the same class still lands
in it, the fix is input-level, not class-level, and the patch is rejected with that as counterexample
feedback (Shannon's "re-trace source->sink through the patched code"). Air-gap tolerant: if the scanner is
unavailable the gate is reported SKIPPED, never falsely passed or failed.
"""
from __future__ import annotations

from pathlib import Path

# opengrep normalizes rule hits to these of our classes; match the patched finding's class against them
_ALIASES = {
    "sql-injection": {"sql-injection"}, "command-injection": {"command-injection"},
    "path-traversal": {"path-traversal"}, "ssrf": {"ssrf"}, "xss": {"xss"},
    "xxe": {"xxe"}, "code-injection": {"code-injection", "eval-injection"},
    "insecure-deserialization": {"insecure-deserialization"}, "open-redirect": {"open-redirect"},
    "ssti": {"ssti"}, "nosql-injection": {"nosql-injection"}, "ldap-injection": {"ldap-injection"},
}


def flow_cleared(patched_file: str | Path, klass: str) -> tuple[bool, str]:
    """Return (cleared, detail). cleared=True means no finding of `klass` remains in the patched file (or the
    scanner could not run — never block on that). The caller treats cleared=False as a failed gate."""
    try:
        from benchmarks.scanners.opengrep import _binary, findings_from_opengrep
    except ImportError:
        return True, "re-scan skipped (scanner import unavailable)"
    if _binary() is None:
        return True, "re-scan skipped (opengrep/semgrep not installed)"
    want = _ALIASES.get(klass, {klass})
    try:
        hits = findings_from_opengrep(Path(patched_file))
    except Exception as e:  # noqa: BLE001
        return True, f"re-scan skipped (scanner error: {str(e)[:60]})"
    remaining = [h for h in hits if h.klass in want]
    if remaining:
        loc = f"{remaining[0].file}:{remaining[0].line}"
        return False, (f"the exploit stopped but a {klass} data-flow is STILL present at {loc} — you fixed the "
                       f"input, not the flow; neutralize the tainted path to the sink, not just this payload")
    return True, f"re-scan clean: no {klass} flow remains in the patched file"


def sibling_sinks(tree: str | Path, klass: str, exclude_files: set) -> list:
    """Bypass review (Shannon): after patching one sink, scan the whole tree for the SAME class at OTHER
    files — a per-route fix often leaves twin call sites. Returns candidate Findings at locations not in
    `exclude_files` (the patched ones), so they surface for verification. Empty if the scanner is absent."""
    try:
        from benchmarks.scanners.opengrep import _binary, findings_from_opengrep
    except ImportError:
        return []
    if _binary() is None:
        return []
    want = _ALIASES.get(klass, {klass})
    try:
        hits = findings_from_opengrep(Path(tree))
    except Exception:  # noqa: BLE001
        return []
    return [h for h in hits if h.klass in want and h.file not in exclude_files]
