"""Trivy report -> candidate Findings: vulnerabilities (with fix), misconfig, secrets."""
import json
from benchmarks.scanners.trivy import findings_from_trivy


def test_trivy_vuln_misconfig_secret(tmp_path):
    rpt = {"Results": [
        {"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash", "InstalledVersion": "4.17.11",
             "FixedVersion": "4.17.21", "Severity": "HIGH", "Title": "command injection",
             "CweIDs": ["CWE-77"], "PrimaryURL": "http://x"}]},
        {"Target": "Dockerfile", "Type": "dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Title": "run as root", "Severity": "MEDIUM", "CauseMetadata": {"StartLine": 3}}]},
        {"Target": ".env", "Secrets": [
            {"RuleID": "aws-access-key", "Title": "AWS key", "Severity": "CRITICAL", "StartLine": 1, "Match": "AKIA..."}]},
    ]}
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(rpt))
    fs = findings_from_trivy(p)
    by = {f.klass: f for f in fs}
    assert len(fs) == 3
    dep = by["vulnerable-dependency"]
    assert dep.evidence["package"] == "lodash" and dep.evidence["fixed"] == "4.17.21"
    assert dep.cwe == "CWE-77" and dep.severity == "high" and dep.status == "candidate"
    assert by["misconfiguration"].line == 3 and by["misconfiguration"].rule == "DS002"
    assert by["hardcoded-secret"].severity == "critical" and by["hardcoded-secret"].line == 1


def test_trivy_empty_report(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps({"Results": []}))
    assert findings_from_trivy(p) == []
