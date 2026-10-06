"""
Vulnerable-dependency detection for a Node application, OFFLINE by default.

Deployments are often network-restricted, so the default path never touches the network: the lockfile's
dependency graph is matched against a vendored advisory snapshot (`src/jsauto/advisories.py`, built
ahead of time). `npm audit` is kept as an explicit opt-in (`allow_network=True`) for use where the
registry is permitted.

Scope is RUNTIME dependencies only. Packages the lockfile marks `dev` are ignored: they never run in
production, and a typical app has about three times as many advisories once test runners, task runners
and browsers are included.

Attribution follows npm's own model: a finding is reported against the DIRECT dependency that brings the
vulnerable code in, with the vulnerable (possibly transitive) packages listed under it, because the fix
is a change to that direct dependency.

Never an empty list that reads as "clean": a missing lockfile or snapshot, or a failed audit, is an
`error` and says what is missing.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from src.jsauto import advisories as adv
from src.jsauto.findings import Finding

_SEV = {"info": "low", "low": "low", "moderate": "medium", "medium": "medium", "high": "high",
        "critical": "critical"}
_RANK = ["low", "medium", "high", "critical"]


# -- lockfile graph ----------------------------------------------------------------------------------

def _resolve(packages: dict, base: str, name: str) -> Optional[str]:
    """Node's resolution: nearest node_modules/<name> from `base`, walking up to the root."""
    while True:
        path = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if path in packages:
            return path
        if not base:
            return None
        base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""


def _reachable(packages: dict, start: str) -> dict:
    """{path: via_chain} for every runtime package reachable from `start`, including itself."""
    seen = {start: [packages[start].get("name") or start.rsplit("node_modules/", 1)[-1]]}
    stack = [start]
    while stack:
        cur = stack.pop()
        entry = packages[cur]
        for dep in {**(entry.get("dependencies") or {}), **(entry.get("optionalDependencies") or {})}:
            path = _resolve(packages, cur, dep)
            if path is None or path in seen or packages[path].get("dev"):
                continue
            seen[path] = seen[cur] + [dep]
            stack.append(path)
    return seen


def _name(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _version_key_major(v: str) -> Optional[int]:
    k = adv.parse_version(v)
    return k[0] if k else None


# -- offline audit ----------------------------------------------------------------------------------------

def audit_offline(root: Path, snapshot: Optional[dict] = None) -> dict:
    root = Path(root).resolve()
    pkg_json = root / "package.json"
    if not pkg_json.exists():
        return {"findings": [], "error": "no package.json", "totals": {}, "mode": "offline"}
    lock = root / "package-lock.json"
    if not lock.exists():
        return {"findings": [], "error": "no package-lock.json: installed versions are unknown, so the "
                                         "dependencies cannot be matched; this is NOT a clean result",
                "totals": {}, "mode": "offline"}
    try:
        snap = snapshot if snapshot is not None else adv.load()
    except FileNotFoundError as e:
        return {"findings": [], "error": str(e), "totals": {}, "mode": "offline"}
    data = json.loads(lock.read_text())
    packages = data.get("packages")
    if not packages:
        return {"findings": [], "error": "lockfile v1 (no `packages` map) is not supported offline; "
                                         "regenerate it with a current npm", "totals": {}, "mode": "offline"}
    table = snap["packages"]
    declared = json.loads(pkg_json.read_text()).get("dependencies", {}) or {}
    findings: list[Finding] = []
    totals = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for dep in sorted(declared):
        start = _resolve(packages, "", dep)
        if start is None:
            continue
        hits = []                                   # (advisory, package path, version, chain)
        for path, chain in _reachable(packages, start).items():
            ver = packages[path].get("version", "")
            for a in table.get(_name(path), []):
                if adv.affected(ver, a["ranges"], a.get("versions")):
                    hits.append((a, path, ver, chain))
        if not hits:
            continue
        top = max((h[0]["severity"] for h in hits), key=lambda s: _RANK.index(_SEV.get(s, "medium")))
        top = _SEV.get(top, "medium")
        totals[top] += 1
        direct_ver = packages[start].get("version", "")
        own = [h for h in hits if h[1] == start]
        fix = ""
        if own:                                     # the direct package itself is affected: a published fix
            fixes = [adv.first_fix(direct_ver, h[0]["ranges"]) for h in own]
            fixes = [f for f in fixes if f]
            fix = max(fixes, key=lambda f: adv.parse_version(f)) if fixes else ""
        ids = sorted({h[0]["id"] for h in hits})
        titles = list(dict.fromkeys(h[0]["summary"] for h in hits))[:4]
        via = sorted({_name(h[1]) for h in hits if h[1] != start})[:6]
        findings.append(Finding(
            id="", source="advisory-snapshot", klass="vulnerable-dependency", file="package.json",
            rule=f"advisory:{dep}", cwe=next((h[0]["cwe"] for h in hits if h[0]["cwe"]), ""),
            owasp="A06:2021", severity=top, confidence="high",
            message=f"{dep} {direct_ver} has known vulnerabilities: " + ("; ".join(titles) or ", ".join(ids)),
            evidence={"package": dep, "installed": direct_ver, "advisories": titles, "advisory_ids": ids,
                      "via_packages": via, "fix_version": fix,
                      "fix_is_major_bump": bool(fix and _version_key_major(fix) != _version_key_major(direct_ver)),
                      "fix_available": bool(fix),
                      "snapshot": {"built": snap.get("meta", {}).get("built"),
                                   "advisories": snap.get("meta", {}).get("advisories")}}))
    return {"findings": findings, "error": "", "totals": totals, "mode": "offline",
            "snapshot": snap.get("meta", {})}


# -- opt-in: npm audit (needs the registry) ---------------------------------------------------------------

def audit_with_registry(root: Path, timeout: int = 120) -> dict:
    """`npm audit`: only for environments where the registry is permitted."""
    root = Path(root).resolve()
    if not (root / "package.json").exists():
        return {"findings": [], "error": "no package.json", "totals": {}, "mode": "registry"}
    if not (root / "package-lock.json").exists():
        return {"findings": [], "error": "no package-lock.json: versions cannot be audited without an "
                                         "install; not reporting this as 'no vulnerabilities'",
                "totals": {}, "mode": "registry"}
    try:
        proc = subprocess.run(["npm", "audit", "--package-lock-only", "--omit=dev", "--json"],
                              cwd=root, capture_output=True, text=True, timeout=timeout)
        data = json.loads(proc.stdout)
    except FileNotFoundError:
        return {"findings": [], "error": "npm is not installed", "totals": {}, "mode": "registry"}
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": f"npm audit timed out after {timeout}s", "totals": {}, "mode": "registry"}
    except ValueError:
        return {"findings": [], "error": "npm audit returned no JSON: " + (proc.stderr or "")[:200],
                "totals": {}, "mode": "registry"}
    if "error" in data:
        return {"findings": [], "error": f"npm audit failed: {data['error'].get('summary', data['error'])}"[:240],
                "totals": {}, "mode": "registry"}
    installed = {name[len("node_modules/"):]: meta.get("version", "")
                 for name, meta in json.loads((root / "package-lock.json").read_text()).get("packages", {}).items()
                 if name.startswith("node_modules/") and name.count("node_modules/") == 1}
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
            owasp="A06:2021", severity=_SEV.get(v.get("severity", "medium"), "medium"), confidence="high",
            message=f"{name} {installed.get(name, '?')} has known vulnerabilities: "
                    + ("; ".join(titles) if titles else "via " + ", ".join(via_pkgs)),
            evidence={"package": name, "installed": installed.get(name, ""), "range": v.get("range", ""),
                      "advisories": titles, "via_packages": via_pkgs, "fix_version": fix,
                      "fix_is_major_bump": bool(isinstance(fa, dict) and fa.get("isSemVerMajor")),
                      "fix_available": bool(fa)}))
    return {"findings": findings, "error": "", "totals": data.get("metadata", {}).get("vulnerabilities", {}),
            "mode": "registry"}


def audit(root: Path, allow_network: bool = False, snapshot: Optional[dict] = None, timeout: int = 120) -> dict:
    """Offline against the vendored snapshot unless the network is explicitly allowed."""
    if allow_network:
        return audit_with_registry(root, timeout)
    return audit_offline(root, snapshot)
