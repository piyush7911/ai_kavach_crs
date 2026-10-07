"""Vuln report in the required CSV format:
    s. no. | vuln title | severity | description | vuln code location/path | steps to reproduce (evidence)
Rows are the CONFIRMED findings only (the claimed vulnerabilities — the format has no status column, so
candidates/unconfirmed are not asserted here; they stay in the JSON). Sorted critical -> low. The evidence
column is the reproducible PoC (payload + request + expected-vs-observed + logged exchange ids).
"""
from __future__ import annotations

import csv

_HEADER = ["s. no.", "vuln title", "severity", "description", "vuln code location/path",
           "steps to reproduce (evidence)"]

# human titles per class (fallback: title-case the class)
_TITLE = {
    "sql-injection": "SQL Injection", "nosql-injection": "NoSQL Injection",
    "command-injection": "Command Injection", "path-traversal": "Path Traversal",
    "ssrf": "Server-Side Request Forgery (SSRF)", "xxe": "XML External Entity (XXE)",
    "insecure-deserialization": "Insecure Deserialization", "open-redirect": "Open Redirect",
    "xss": "Cross-Site Scripting (XSS)", "xss-reflected": "Reflected Cross-Site Scripting (XSS)",
    "ssti": "Server-Side Template Injection (SSTI)", "idor": "Insecure Direct Object Reference (IDOR)",
    "broken-object-level-auth": "Broken Object-Level Authorization (BOLA)",
    "mass-assignment": "Mass Assignment", "excessive-data-exposure": "Excessive Data Exposure",
    "sensitive-data-exposure": "Sensitive Data Exposure", "user-enumeration": "Username Enumeration",
    "clickjacking": "Clickjacking (missing framing protection)", "cookie-flags": "Insecure Cookie Flags",
    "cookie-samesite": "Cookie Missing SameSite", "cors-misconfig": "CORS Misconfiguration",
    "csrf-missing": "Cross-Site Request Forgery (missing token)", "no-rate-limit": "Missing Rate Limiting",
    "jwt-none-alg": "JWT alg=none Accepted", "jwt-weak-secret": "JWT Weak Signing Secret",
    "jwt-no-expiry": "JWT Missing Expiry", "weak-hash": "Weak Password Hash",
    "weak-cipher": "Weak Cipher", "weak-random": "Insecure Randomness",
    "web-cache-poisoning": "Web Cache Poisoning", "http-request-smuggling": "HTTP Request Smuggling",
    "server-error": "Unhandled Server Error", "header-injection": "HTTP Response Header Injection",
    "predictable-session-id": "Predictable Session ID", "hardcoded-secret": "Hardcoded Secret",
}
_SEV_OUT = {"critical": "critical", "high": "high", "medium": "med", "med": "med", "low": "low", "info": "low"}
_SEV_RANK = {"critical": 0, "high": 1, "med": 2, "low": 3}


def _title(klass: str) -> str:
    return _TITLE.get(klass, klass.replace("-", " ").replace("_", " ").title())


def _severity(f) -> str:
    return _SEV_OUT.get((getattr(f, "severity", "") or "medium").lower(), "med")


def _location(f) -> str:
    ev = f.evidence or {}
    if ev.get("route"):
        return ev["route"] + (f"  (sink: {ev['sink']['file']}:{ev['sink']['line']})" if ev.get("sink") else "")
    if f.file and f.file != "(runtime)":
        return f"{f.file}:{f.line}" if f.line else f.file
    return ev.get("location", "") or "(runtime)"


def _steps(f) -> str:
    poc = f.poc or {}
    ev = f.evidence or {}
    lines = []
    if poc.get("payload"):
        lines.append(f"Payload: {poc['payload']}")
    request = (poc.get("request") or "").strip() or ev.get("route", "")   # fall back to the route for live findings
    if request:
        lines.append(f"Request: {request}")
    if poc.get("expected"):
        lines.append(f"Expected (if secure): {poc['expected']}")
    actual = poc.get("actual") or f.reason
    if actual:
        lines.append(f"Observed: {actual}")
    if getattr(f, "http_exchange_ids", None):
        lines.append(f"Logged exchange ids: {', '.join(map(str, f.http_exchange_ids))}")
    if not lines:                                        # fall back to the replayable exploit + reason
        if f.exploit:
            lines.append(f"Exploit: {f.exploit.get('method', 'GET')} {f.exploit.get('path', '')}")
        if f.reason:
            lines.append(f"Observed: {f.reason}")
    return "\n".join(lines)


def to_rows(findings) -> list[list]:
    """Confirmed findings -> CSV rows (list), sorted critical->low."""
    confirmed = [f for f in findings if getattr(f, "status", "") == "confirmed"]
    confirmed.sort(key=lambda f: (_SEV_RANK.get(_severity(f), 3), f.klass))
    rows = []
    for i, f in enumerate(confirmed, 1):
        rows.append([i, _title(f.klass), _severity(f), (f.message or f.reason or "").strip(),
                     _location(f), _steps(f)])
    return rows


def write_csv(findings, path: str) -> int:
    """Write the confirmed-vuln report CSV. Returns the row count."""
    rows = to_rows(findings)
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(_HEADER)
        w.writerows(rows)
    return len(rows)
