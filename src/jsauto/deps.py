"""
Vulnerable-dependency detection for a Node application.

Scope is RUNTIME dependencies only (`npm audit --omit=dev`). A first pass over a typical app
returns ~3x more advisories once dev tooling (test runners, task runners, browsers) is included;
those never run in production and a fix for them is noise to a reviewer.

NETWORK NOTE: `npm audit` asks the npm registry's advisory endpoint, so this module needs
outbound access to registry.npmjs.org. Nothing is sent but package names and versions from the
lockfile. Where that is not allowed, the call fails and says so (`error`); it never returns an
empty list that would read as "no vulnerable dependencies".
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from src.jsauto.findings import Finding

_SEV = {"info": "low", "low": "low", "moderate": "medium", "high": "high", "critical": "critical"}


def _installed_versions(root: Path) -> dict:
    lock = root / "package-lock.json"
    if not lock.exists():
        return {}
    data = json.loads(lock.read_text())
    return {name[len("node_modules/"):]: meta.get("version", "")
            for name, meta in data.get("packages", {}).items()
            if name.startswith("node_modules/") and name.count("node_modules/") == 1}


def audit(root: Path, timeout: int = 120) -> dict:
    """{"findings": [Finding], "error": str, "totals": dict}"""
    root = Path(root).resolve()
    if not (root / "package.json").exists():
        return {"findings": [], "error": "no package.json", "totals": {}}
    if not (root / "package-lock.json").exists():
        return {"findings": [], "error": "no package-lock.json: versions cannot be audited without "
                                         "an install; not reporting this as 'no vulnerabilities'",
                "totals": {}}
    try:
        proc = subprocess.run(["npm", "audit", "--package-lock-only", "--omit=dev", "--json"],
                              cwd=root, capture_output=True, text=True, timeout=timeout)
        data = json.loads(proc.stdout)
    except FileNotFoundError:
        return {"findings": [], "error": "npm is not installed", "totals": {}}
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": f"npm audit timed out after {timeout}s", "totals": {}}
    except ValueError:
        return {"findings": [], "error": "npm audit returned no JSON: " + (proc.stderr or "")[:200],
                "totals": {}}
    if "error" in data:
        return {"findings": [], "error": f"npm audit failed: {data['error'].get('summary', data['error'])}"[:240],
                "totals": {}}

    installed = _installed_versions(root)
    findings: list[Finding] = []
    for name, v in sorted(data.get("vulnerabilities", {}).items()):
        if not v.get("isDirect"):
            continue
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        titles = [a.get("title", "") for a in advisories][:4]
        via_pkgs = [x for x in v.get("via", []) if isinstance(x, str)][:4]
        fa = v.get("fixAvailable")
        fix = fa.get("version", "") if isinstance(fa, dict) else ""
        findings.append(Finding(
            id="", source="npm-audit", klass="vulnerable-dependency", file="package.json",
            rule=f"npm-audit:{name}", cwe=(advisories[0].get("cwe") or [""])[0] if advisories else "",
            owasp="A06:2021", severity=_SEV.get(v.get("severity", "medium"), "medium"),
            confidence="high",
            message=f"{name} {installed.get(name, '?')} has known vulnerabilities: "
                    + ("; ".join(titles) if titles else "via " + ", ".join(via_pkgs)),
            evidence={"package": name, "installed": installed.get(name, ""), "range": v.get("range", ""),
                      "advisories": titles, "via_packages": via_pkgs,
                      "fix_version": fix, "fix_is_major_bump": bool(isinstance(fa, dict) and fa.get("isSemVerMajor")),
                      "fix_available": bool(fa)},
        ))
    return {"findings": findings, "error": "", "totals": data.get("metadata", {}).get("vulnerabilities", {})}
