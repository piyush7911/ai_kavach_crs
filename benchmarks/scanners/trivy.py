"""Ingest a Trivy report as Findings — the dependency / container / IaC / secrets layer our HTTP engine
deliberately does not cover.

Trivy is SCA + misconfig + secrets: it matches your dependency and OS-package versions against a CVE
database, flags Dockerfile/K8s/Terraform misconfigs, and greps for committed secrets. None of that is
confirmable by sending an HTTP request (a CVE in a library is not a live endpoint), so these come in as
candidates — but a dependency CVE carries its own fix (bump to `FixedVersion`), which is the determinate
remediation our dependency-fix path already applies. This adapter fills the SCA gap; it does not pretend
to HTTP-confirm a CVE.

Parses `trivy ... --format json` output: Results[].Vulnerabilities / .Misconfigurations / .Secrets.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.jsauto.findings import Finding

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}


def findings_from_trivy(report_path: str | Path) -> list[Finding]:
    report = json.loads(Path(report_path).read_text())
    findings, i = [], 0

    def add(**kw):
        nonlocal i
        i += 1
        findings.append(Finding(id=f"TRIVY-{i:03d}", source="trivy", status="candidate",
                                confidence="high", **kw))

    for res in report.get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            cwe = (v.get("CweIDs") or [""])[0]
            fixed = v.get("FixedVersion", "")
            add(klass="vulnerable-dependency", file=target, cwe=cwe,
                rule=v.get("VulnerabilityID", ""), severity=_SEV.get(v.get("Severity", ""), "medium"),
                message=f"{v.get('PkgName','')} {v.get('InstalledVersion','')} — {v.get('Title', v.get('VulnerabilityID',''))}"
                        + (f" (fix: {fixed})" if fixed else " (no fix available)"),
                evidence={"package": v.get("PkgName", ""), "installed": v.get("InstalledVersion", ""),
                          "fixed": fixed, "cve": v.get("VulnerabilityID", ""), "type": res.get("Type", ""),
                          "url": v.get("PrimaryURL", "")})
        for m in res.get("Misconfigurations", []) or []:
            cm = m.get("CauseMetadata", {}) or {}
            add(klass="misconfiguration", file=target, line=cm.get("StartLine", 0) or 0,
                rule=m.get("ID", ""), severity=_SEV.get(m.get("Severity", ""), "medium"),
                message=f"{m.get('ID','')}: {m.get('Title','')}",
                evidence={"resolution": m.get("Resolution", ""), "type": res.get("Type", "")})
        for s in res.get("Secrets", []) or []:
            add(klass="hardcoded-secret", file=target, line=s.get("StartLine", 0) or 0,
                rule=s.get("RuleID", ""), severity=_SEV.get(s.get("Severity", ""), "high"),
                message=f"{s.get('RuleID','')}: {s.get('Title','')}",
                evidence={"match": s.get("Match", "")[:80]})
    return findings
