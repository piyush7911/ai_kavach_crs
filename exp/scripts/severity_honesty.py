"""Severity + reporting honesty, adapted from Shannon (AGPL — ideas only).

Three deterministic rules that make a finding's severity/claim honest rather than a restatement of the CWE:
  P6a self-refutation: if the severity rationale contains the reason it does NOT matter ("attacker can't
       read it", "only the victim sees it", "requires access they already have"), the author wrote the
       close argument — lower a tier and flag.
  P6b no-consequence floor: if nobody ends up holding something they shouldn't, there is no tier.
  R1  anti-overstatement: a CONFIRMED finding must claim what was OBSERVED — hedges ("theoretical",
       "potential", "could allow") mean unsettled; flag them.
  R2  consequence model: severity is adjusted by preconditions (every precondition lowers it) and by
       reachability (auth-gated routes are lower), with a one-line rationale — not a generic table lookup.
Conservative: it only ever LOWERS or flags, never inflates, so it cannot manufacture a false high.
"""
from __future__ import annotations

import re

_TIERS = ["info", "low", "medium", "high", "critical"]
_REFUTE = re.compile(r"(?i)(can'?t|cannot|unable to) (read|access|reach|see)|only the (victim|attacker|user)"
                     r"|requires? (access|privilege|role)s? (they|it) already|already authenticated"
                     r"|self[- ]?(xss|only)|no (real )?impact|not exploitable without")
_HEDGE = re.compile(r"(?i)\b(theoretical|potential(ly)?|possibl[ey]|could allow|may allow|might allow|in theory"
                    r"|appears? to|seems? to|likely)\b")
# classes that need a state-changing / cross-user consequence to carry a tier at all
_NEEDS_CONSEQUENCE = {"clickjacking", "cookie-samesite", "csrf-missing", "jwt-no-expiry"}


def _lower(sev: str, by: int = 1) -> str:
    i = _TIERS.index(sev) if sev in _TIERS else 2
    return _TIERS[max(0, i - by)]


def refine(finding: dict) -> dict:
    """Return {severity, severity_rationale, warnings[]} — honest severity for this finding. Reads
    severity, klass, reason, status, and reachability/evidence. Only lowers/flags."""
    sev = (finding.get("severity") or "medium").lower()
    klass = finding.get("klass", "")
    reason = f"{finding.get('reason','')} {finding.get('severity_change_conditions','')}"
    status = finding.get("status", "")
    reach = finding.get("reachability", "") or (finding.get("evidence") or {}).get("reachability", "")
    warnings, parts = [], []

    # R2: preconditions lower severity
    if reach == "AUTHENTICATED":
        sev = _lower(sev)
        parts.append("auth-gated route (precondition) → lowered")

    # P6a: a rationale that argues the finding away
    if _REFUTE.search(reason):
        sev = _lower(sev)
        warnings.append("self-refuting rationale: the severity text contains the reason it does not matter")
        parts.append("self-refutation detected → lowered")

    # R1: a confirmed finding stated with hedges is overstated/unsettled
    if status == "confirmed" and _HEDGE.search(f"{finding.get('message','')} {finding.get('reason','')}"):
        warnings.append("overstatement/hedge in a confirmed claim — state what was observed, not 'potential/could'")

    # P6b: no-consequence floor
    if klass in _NEEDS_CONSEQUENCE and "state-chang" not in reason.lower() and "cross" not in reason.lower():
        if _TIERS.index(sev) > _TIERS.index("low"):
            sev = "low"
            parts.append("no demonstrated cross-user/state-changing consequence → floored to low")

    return {"severity": sev, "severity_rationale": "; ".join(parts) or "severity kept from profile",
            "warnings": warnings}


def _self_check():
    # auth precondition lowers
    r = refine({"severity": "high", "klass": "sql-injection", "status": "confirmed",
                "reachability": "AUTHENTICATED", "reason": "injection confirmed"})
    assert r["severity"] == "medium" and "auth-gated" in r["severity_rationale"]
    # self-refuting rationale lowers + warns
    r = refine({"severity": "high", "klass": "idor", "status": "confirmed",
                "reason": "idor but attacker can't read the returned blob"})
    assert r["severity"] == "medium" and r["warnings"]
    # no-consequence floor for clickjacking
    r = refine({"severity": "medium", "klass": "clickjacking", "status": "confirmed", "reason": "no XFO header"})
    assert r["severity"] == "low"
    # hedge in a confirmed claim is flagged (severity unchanged here)
    r = refine({"severity": "high", "klass": "ssrf", "status": "confirmed",
                "message": "this could allow SSRF", "reason": "oob hit"})
    assert any("hedge" in w for w in r["warnings"])
    # a clean confirmed critical is untouched
    r = refine({"severity": "critical", "klass": "command-injection", "status": "confirmed",
                "reason": "marker 31338 returned"})
    assert r["severity"] == "critical" and not r["warnings"]
    print("severity_honesty self-check: OK")


if __name__ == "__main__":
    _self_check()
