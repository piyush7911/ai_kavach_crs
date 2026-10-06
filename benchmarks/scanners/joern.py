"""Joern (Apache-2.0 code property graph + cross-file taint) as a CANDIDATE source.

Joern's inter-procedural taint finds source->sink flows across functions and files that per-file pattern
rules (and even Opengrep's taint) miss — on VulnerableApp it reaches 46/52 injection levels vs Opengrep's
6-10. Its false alarms are structural (it cannot see a validation branch or a parser-hardening flag), but
that costs us nothing: these are CANDIDATES, and our oracle confirms — a flow that is really safe simply
never fires. We read the TSV that exp/scripts/joern_taint.sc emits (produced offline; this adapter does not
run Joern) and emit one Finding per FLOW, anchored to the SOURCE handler so `correlate` can map it to a
route, with the sink kept in evidence for the fix/report.
"""
from __future__ import annotations

from pathlib import Path

from src.jsauto.findings import Finding

# joern class label -> our oracle/vocabulary class (so flows join the correlate/confirm/report path)
_CLASS = {"sql-injection": "sql-injection", "nosql-injection": "nosql-injection", "xss": "xss",
          "command-injection": "command-injection", "code-injection": "code-injection",
          "eval": "eval-injection", "deserialization": "insecure-deserialization",
          "ldap-injection": "ldap-injection", "ssrf": "ssrf", "xxe": "xxe",
          "open-redirect": "open-redirect", "path-traversal": "path-traversal"}


def findings_from_joern(tsv_path: str | Path) -> list[Finding]:
    """Parse a Joern taint TSV into candidate Findings. FLOW row:
    FLOW <class> <src_file> <src_line> <src_func> <sink_file> <sink_line> <sink_func>."""
    path = Path(tsv_path)
    if not path.exists():
        return []
    out, i = [], 0
    for line in path.read_text(errors="replace").splitlines():
        cols = line.split("\t")
        if not cols or cols[0] != "FLOW" or len(cols) < 8:
            continue                                     # skip META / malformed rows
        klass_raw, sfile, sline, sfunc, kfile, kline, kfunc = cols[1:8]
        i += 1
        try:
            line_no = max(int(sline), 0)
        except ValueError:
            line_no = 0
        out.append(Finding(
            id=f"JOERN-{i:03d}", source="joern", status="candidate", confidence="medium",
            klass=_CLASS.get(klass_raw, klass_raw),
            file=sfile.replace("\\", "/"), line=line_no, function=sfunc,
            rule="joern-taint", message=f"taint flow {klass_raw}: {sfunc} -> {kfunc}",
            evidence={"param": "", "lines": [line_no], "engine": "joern",
                      "sink": {"file": kfile.replace("\\", "/"), "line": kline, "function": kfunc}}))
    return out
