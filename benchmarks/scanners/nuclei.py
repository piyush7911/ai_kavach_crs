"""Ingest a Nuclei report (JSONL) as candidate Findings + a route source — same contract as the ZAP
adapter, so it rides the same `confirm_candidates` path (our oracle re-tests each alert; real ones get
proven, false positives stay candidates).

Nuclei emits one JSON object per line (`nuclei -jsonl -o out.jsonl`). Each hit carries the matched URL,
severity, and a classification (CWE/CVE) plus tags — we map those to our oracle classes and read the
route+param from `matched-at`.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from benchmarks.scanners.zap import _CWE_CLASS
from src.jsauto.findings import Finding

# tag / template-id keyword -> our oracle class (fallback when there is no CWE)
_TAG_CLASS = [
    ("sqli", "sql-injection"), ("sql-injection", "sql-injection"), ("xss", "xss"),
    ("lfi", "path-traversal"), ("path-traversal", "path-traversal"), ("traversal", "path-traversal"),
    ("rfi", "rfi"), ("rce", "command-injection"), ("command-injection", "command-injection"),
    ("cmd-injection", "command-injection"), ("ssrf", "ssrf"), ("redirect", "open-redirect"),
    ("xxe", "xxe"), ("idor", "broken-object-level-auth"),
]
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low", "unknown": "low"}


def _klass(info: dict, template_id: str) -> str | None:
    for cwe in (info.get("classification") or {}).get("cwe-id", []) or []:
        num = str(cwe).upper().replace("CWE-", "")
        if num in _CWE_CLASS:
            return _CWE_CLASS[num]
    hay = " ".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [info.get("tags", "")])
    hay = (hay + " " + template_id).lower()
    for kw, cls in _TAG_CLASS:
        if kw in hay:
            return cls
    return None


def _records(report_path: str | Path) -> list[dict]:
    text = Path(report_path).read_text().strip()
    if not text:
        return []
    if text[0] == "[":                                   # also accept a JSON array
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def findings_from_nuclei(report_path: str | Path) -> list[Finding]:
    findings, seen, i = [], set(), 0
    for rec in _records(report_path):
        info = rec.get("info", {}) or {}
        klass = _klass(info, rec.get("template-id", "") or rec.get("templateID", ""))
        if not klass:
            continue
        uri = rec.get("matched-at") or rec.get("matched") or rec.get("host", "")
        p = urlparse(uri)
        path = p.path or "/"
        param = next(iter(parse_qs(p.query, keep_blank_values=True)), "")
        key = (klass, path, param)
        if key in seen:
            continue
        seen.add(key)
        i += 1
        findings.append(Finding(
            id=f"NUCLEI-{i:03d}", source="nuclei", klass=klass, file="(runtime)",
            rule=rec.get("template-id", ""), severity=_SEV.get(str(info.get("severity", "")).lower(), "medium"),
            confidence="low", status="candidate",
            message=f"Nuclei '{info.get('name', rec.get('template-id',''))}' at {path}",
            evidence={"route": f"GET {path}", "param": param, "uri": uri}))
    return findings


def routes_from_nuclei(report_path: str | Path):
    """Use Nuclei's matched URLs as a route source (path + any query params), like routes_from_zap."""
    from src.pyauto.probes import Route
    routes: dict = {}
    for rec in _records(report_path):
        uri = rec.get("matched-at") or rec.get("matched") or ""
        if not uri:
            continue
        p = urlparse(uri)
        routes.setdefault(("GET", p.path or "/"), set()).update(parse_qs(p.query, keep_blank_values=True).keys())
    return [Route(m, pth, query_fields=sorted(ps)) for (m, pth), ps in sorted(routes.items())]
