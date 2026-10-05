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

    def to_dict(self) -> dict:
        return asdict(self)


def dump(findings: list[Finding], path, extra: Optional[dict] = None) -> None:
    body = {"findings": [f.to_dict() for f in findings]}
    body.update(extra or {})
    with open(path, "w") as fh:
        json.dump(body, fh, indent=2)
