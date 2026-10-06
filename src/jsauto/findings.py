"""
A language-neutral finding, shared by static detection, dependency audit and dynamic probes.

`status` is deliberately explicit:
  candidate  a detector flagged it; nothing has shown it is exploitable
  confirmed  a replayable exploit succeeded against a running instance
  informational reported for review but not counted as a defect (for example a credential in a seed script)
  suppressed a detector flagged it and we decided it is not a defect; the reason is kept
"""

import json
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Finding:
    id: str
    source: str                    # semgrep | npm-audit | probe
    klass: str                     # ssrf | eval-injection | nosql-injection | open-redirect | ...
    file: str                      # relative to the target root, POSIX
    line: int = 0
    end_line: int = 0
    function: str = ""             # enclosing function, when one exists
    rule: str = ""
    cwe: str = ""
    owasp: str = ""
    severity: str = "medium"       # low | medium | high | critical
    confidence: str = "medium"     # low | medium | high
    message: str = ""
    status: str = "candidate"
    reason: str = ""               # why suppressed, or what confirmed it
    evidence: dict = field(default_factory=dict)
    exploit: Optional[dict] = None  # replayable HTTP request: {method, path, headers, body, login_as, success_if}
    # Security enrichment for a CONFIRMED finding (shape adapted from bug-hunter, MIT, © codexstar69).
    # Unlike a static tool, our PoC's request/actual are what we really sent and got back over HTTP.
    stride: str = ""                # Spoofing|Tampering|Repudiation|InfoDisclosure|DoS|ElevationOfPrivilege
    reachability: str = ""          # EXTERNAL | AUTHENTICATED | INTERNAL | UNREACHABLE
    exploitability: str = ""        # EASY | MEDIUM | HARD
    cvss: str = ""                  # CVSS 3.1 vector string
    poc: dict = field(default_factory=dict)  # {payload, request, expected, actual} — actually sent/observed

    def to_dict(self) -> dict:
        return asdict(self)


# Security profile per vulnerability class, shared by both backends: (STRIDE, exploitability, CVSS 3.1
# vector). Shape adapted from bug-hunter (MIT, © codexstar69). Keys cover the Python and JS klasses.
SECURITY_PROFILE = {
    "excessive-data-exposure": ("InfoDisclosure", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "injection": ("Tampering", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "nosql-injection": ("Tampering", "EASY", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "eval-injection": ("ElevationOfPrivilege", "EASY", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "xss": ("Tampering", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    "ssrf": ("InfoDisclosure", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"),
    "command-injection": ("ElevationOfPrivilege", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "path-traversal": ("InfoDisclosure", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "open-redirect": ("Spoofing", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "idor": ("ElevationOfPrivilege", "EASY", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "broken-object-level-auth": ("ElevationOfPrivilege", "EASY", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "user-enumeration": ("InfoDisclosure", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "mass-assignment": ("ElevationOfPrivilege", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "insecure-deserialization": ("ElevationOfPrivilege", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    # live/HTTP deterministic classes (language-agnostic PROVE stage) — facts or replayed exploits, FP-safe
    "clickjacking": ("Tampering", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "cookie-flags": ("InfoDisclosure", "MEDIUM", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "cookie-samesite": ("Spoofing", "LOW", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "cors-misconfig": ("InfoDisclosure", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "host-header-reflection": ("Spoofing", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "header-injection": ("Tampering", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"),
    "no-rate-limit": ("DenialOfService", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
    "predictable-session-id": ("Spoofing", "MEDIUM", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "jwt-none-alg": ("Spoofing", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "jwt-weak-secret": ("Spoofing", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "jwt-no-expiry": ("Spoofing", "MEDIUM", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "csrf-missing": ("Tampering", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "sensitive-data-exposure": ("InfoDisclosure", "EASY", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "xss-reflected": ("Tampering", "MEDIUM", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
}


def build_poc(exploit: dict, detail: str) -> dict:
    """A proof-of-concept built from what was actually sent. For the two-request oracles the 'request'
    is the attacking leg and 'actual' is the confirming observation. Used by both backends."""
    ac = (exploit or {}).get("access_control")
    diff = (exploit or {}).get("differential")
    if ac:
        req = ac["request"]
        payload, expected = f"as {ac.get('unauthorized', 'another user')}", "401/403 (not the owner)"
    elif diff:
        req = diff["true_request"]
        payload, expected = "boolean tautology vs contradiction", "identical responses (input does not reach the query)"
    else:
        req = exploit or {}
        payload, expected = req.get("body") or req.get("path", ""), "request denied / no sensitive data"
    request = f"{req.get('method', 'GET')} {req.get('path', '')}" + (f" body={req['body']}" if req.get("body") else "")
    return {"payload": str(payload), "request": request, "expected": expected, "actual": detail}


def apply_security(finding: "Finding", reachability: str, detail: str = "") -> "Finding":
    """Fill the security-enrichment fields on a CONFIRMED finding from the shared profile + its exploit."""
    stride, exploitability, cvss = SECURITY_PROFILE.get(finding.klass, ("", "", ""))
    finding.stride, finding.exploitability, finding.cvss = stride, exploitability, cvss
    finding.reachability = reachability
    finding.poc = build_poc(finding.exploit, detail or finding.reason)
    return finding


def dump(findings: list[Finding], path, extra: Optional[dict] = None) -> None:
    body = {"findings": [f.to_dict() for f in findings]}
    body.update(extra or {})
    with open(path, "w") as fh:
        json.dump(body, fh, indent=2)
