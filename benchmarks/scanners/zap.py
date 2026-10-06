"""Ingest an OWASP ZAP report as candidate Findings for our pipeline.

ZAP (and most scanners) ALERT — they hand you a queue of "might be vulnerable" with false positives and
no fix. We take each alert as a CANDIDATE, then our own oracle re-sends the attack to CONFIRM it (killing
the false positives) and the repair loop fixes + proves it. So this adapter is how we stand on ZAP's
breadth (hundreds of checks) while adding the confirm/fix/prove it never does.

Maps ZAP's CWE id (and alert-name keywords as a fallback) to our oracle classes, and records the URL +
injected parameter so the probe generator can rebuild a replayable exploit. Accepts the traditional ZAP
JSON ({"site":[{"alerts":[{"instances":[...]}]}]}) and the newer flat {"alerts":[...]} shape.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from src.jsauto.findings import Finding

# ZAP CWE id -> our oracle class. CWE is the stable axis (alert names vary by ZAP version/rule pack).
_CWE_CLASS = {
    "89": "sql-injection", "943": "nosql-injection", "78": "command-injection", "77": "command-injection",
    "79": "xss", "22": "path-traversal", "98": "rfi", "918": "ssrf", "601": "open-redirect",
    "611": "xxe", "639": "broken-object-level-auth", "566": "broken-object-level-auth",
    "502": "insecure-deserialization", "327": "weak-crypto", "798": "hardcoded-secret",
}
# fallback: keyword in the alert name -> class (when CWE is missing/0)
_NAME_CLASS = [
    ("sql inject", "sql-injection"), ("command inject", "command-injection"), ("cross site script", "xss"),
    ("path traversal", "path-traversal"), ("directory traversal", "path-traversal"),
    ("remote file", "rfi"), ("server side request", "ssrf"), ("ssrf", "ssrf"),
    ("open redirect", "open-redirect"), ("external entity", "xxe"), ("xxe", "xxe"),
    ("deserial", "insecure-deserialization"),
]


def _klass(alert_name: str, cweid: str) -> str | None:
    if cweid and str(cweid) in _CWE_CLASS:
        return _CWE_CLASS[str(cweid)]
    low = (alert_name or "").lower()
    for kw, cls in _NAME_CLASS:
        if kw in low:
            return cls
    return None


def _alerts(report: dict) -> list:
    """Yield (alert_name, cweid, risk, instances[]) from either ZAP JSON shape."""
    out = []
    if "site" in report:
        for site in report.get("site", []):
            for a in site.get("alerts", []):
                out.append((a.get("alert", ""), a.get("cweid", ""), a.get("riskcode", ""),
                            a.get("instances", [])))
    for a in report.get("alerts", []):                       # flat shape
        out.append((a.get("alert") or a.get("name", ""), a.get("cweid", ""), a.get("riskcode", ""),
                    a.get("instances", [a]) if "uri" in a or "url" in a else a.get("instances", [])))
    return out


_RISK = {"3": "critical", "2": "high", "1": "medium", "0": "low"}


def routes_from_zap(report_path: str | Path):
    """Use a ZAP report as a ROUTE SOURCE (not just alerts): every alert instance records a URL + method +
    the parameter ZAP exercised. ZAP's spider reaches endpoints/params our link-crawl + wordlist miner
    miss (a SPA, auth-walled or JS-built pages), and it hands us the param NAMES directly — so these routes
    go straight into our probe with carriers already known, no mining needed. Returns `Route`s."""
    from urllib.parse import parse_qs, urlparse
    from src.pyauto.probes import Route
    report = json.loads(Path(report_path).read_text())
    routes: dict = {}                                   # (method, path) -> set(param names)
    for _name, _cwe, _risk, instances in _alerts(report):
        for inst in instances or []:
            uri = inst.get("uri") or inst.get("url") or ""
            if not uri:
                continue
            p = urlparse(uri)
            path = p.path or "/"
            params = set(parse_qs(p.query, keep_blank_values=True).keys())
            if inst.get("param"):
                params.add(inst["param"])
            routes.setdefault((inst.get("method", "GET").upper(), path), set()).update(params)
    return [Route(m, pth, query_fields=sorted(ps)) for (m, pth), ps in sorted(routes.items())]


def findings_from_zap(report_path: str | Path) -> list[Finding]:
    """Parse a ZAP JSON report into candidate Findings (status='candidate'; our oracle confirms them)."""
    report = json.loads(Path(report_path).read_text())
    findings, seen, i = [], set(), 0
    for name, cweid, risk, instances in _alerts(report):
        klass = _klass(name, cweid)
        if not klass:
            continue
        for inst in instances or [{}]:
            uri = inst.get("uri") or inst.get("url") or ""
            param = inst.get("param", "")
            path = urlparse(uri).path or "/"
            key = (klass, path, param)
            if key in seen:
                continue
            seen.add(key)
            i += 1
            findings.append(Finding(
                id=f"ZAP-{i:03d}", source="zap", klass=klass, file="(runtime)",
                rule=name, cwe=f"CWE-{cweid}" if cweid else "", severity=_RISK.get(str(risk), "medium"),
                confidence="low", status="candidate",
                message=f"ZAP alert '{name}' on {inst.get('method', 'GET')} {path}"
                        + (f" (param {param})" if param else ""),
                evidence={"route": f"{inst.get('method', 'GET')} {path}", "param": param, "uri": uri}))
    return findings
