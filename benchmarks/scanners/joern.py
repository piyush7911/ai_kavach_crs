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

import shutil
import subprocess
from pathlib import Path

from src.jsauto.findings import Finding

_SCRIPT = Path(__file__).resolve().parents[2] / "exp" / "scripts" / "joern_taint.sc"
_SRC2CPG = {"java": "javasrc2cpg", "python": "pysrc2cpg", "javascript": "jssrc2cpg"}


def _joern_bin(name: str) -> str | None:
    """joern tools from PATH, JOERN_HOME, or the vendored exp/third_party/joern/."""
    hit = shutil.which(name)
    if hit:
        return hit
    import os
    for base in (os.environ.get("JOERN_HOME", ""), "exp/third_party/joern"):
        if base:
            cand = Path(base) / name
            if cand.exists():
                return str(cand)
    return None


def _lang_of(target: Path) -> str:
    exts = {p.suffix for p in target.rglob("*")}
    if ".java" in exts:
        return "java"
    if ".py" in exts:
        return "python"
    if ".js" in exts or ".ts" in exts:
        return "javascript"
    return ""


def run_joern(target: str | Path, out_dir: str | Path, wide: bool = False) -> str | None:
    """Build a CPG and run the taint script to produce a TSV; return its path, or None if Joern is not
    available / the build fails (tolerant — the caller falls back to a pre-built --joern TSV). One command
    when Joern is installed or vendored at exp/third_party/joern."""
    target, out_dir = Path(target), Path(out_dir)
    lang = _lang_of(target)
    joern, build = _joern_bin("joern"), _joern_bin(_SRC2CPG.get(lang, ""))
    if not lang or not joern or not build or not _SCRIPT.exists():
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    cpg, tsv = out_dir / "app.cpg", out_dir / "joern.tsv"
    try:
        r1 = subprocess.run([build, str(target), "-o", str(cpg)], capture_output=True, text=True, timeout=900)
        if r1.returncode != 0 or not cpg.exists():
            return None
        params = ["--param", f"cpgFile={cpg}", "--param", f"lang={lang}", "--param", f"outFile={tsv}"]
        if wide:
            params += ["--param", "wide=true"]
        r2 = subprocess.run([joern, "--script", str(_SCRIPT), *params], capture_output=True, text=True, timeout=900)
        if r2.returncode != 0 or not tsv.exists():
            return None
    except (OSError, subprocess.TimeoutExpired):
        return None
    return str(tsv)


def findings_from_joern_auto(target: str | Path, out_dir: str | Path) -> list[Finding]:
    """One-command Joern: build+run+parse. Empty if Joern is unavailable (then use a pre-built --joern TSV)."""
    tsv = run_joern(target, out_dir)
    return findings_from_joern(tsv) if tsv else []

# joern class label -> our oracle/vocabulary class (so flows join the correlate/confirm/report path)
_CLASS = {"sql-injection": "sql-injection", "nosql-injection": "nosql-injection", "xss": "xss",
          "command-injection": "command-injection", "code-injection": "code-injection",
          "eval": "eval-injection", "deserialization": "insecure-deserialization",
          "ldap-injection": "ldap-injection", "ssrf": "ssrf", "xxe": "xxe",
          "open-redirect": "open-redirect", "path-traversal": "path-traversal"}


def findings_from_joern(tsv_path: str | Path) -> list[Finding]:
    """Parse a Joern taint TSV into candidate Findings. FLOW row (per joern_taint.sc), SINK first:
    FLOW <class> <sink_file> <sink_line> <sink_func> <src_file> <src_line> <src_func>.
    We anchor the Finding to the SOURCE (the request-handler method), so `correlate` can map it to a
    route; the sink (where the fix lands) is kept in evidence."""
    path = Path(tsv_path)
    if not path.exists():
        return []
    out, i = [], 0
    for line in path.read_text(errors="replace").splitlines():
        cols = line.split("\t")
        if not cols or cols[0] != "FLOW" or len(cols) < 8:
            continue                                     # skip META / malformed rows
        klass_raw, kfile, kline, kfunc, sfile, sline, sfunc = cols[1:8]
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
