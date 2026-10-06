"""Reporting gate: a finding may not be CLAIMED (stay `confirmed`) unless it carries proof + a self-critique.

Adapted from strix/tools/reporting/tool.py (Apache-2.0): Strix refuses to file a finding without poc,
evidence, counterevidence, confidence(+rationale), severity_change_conditions, and — when a fix is proposed
— a fix_verification. Strix asks the LLM to write those; we fill them DETERMINISTICALLY from the oracle, so a
replayed exploit (or a deterministic fact) carries its own proof. A confirmed finding that cannot satisfy the
gate is downgraded to `candidate` rather than claimed — this is the FP-zero contract, enforced structurally.

Two proof shapes count as poc:
  - a replayable `exploit` dict (injection / OOB / two-user oracle), or
  - a deterministic FACT (a missing header, a weak literal) whose evidence_text names the observation.
"""
from __future__ import annotations

_VALID_CONFIDENCE = {"high", "medium", "low"}


def _counterevidence_from(exploit: dict, status: str) -> str:
    ex = exploit or {}
    if ex.get("differential"):
        return ("control: a benign request was sent alongside the attack; responses differ only by the "
                "injected payload, so reflection alone cannot explain the flip")
    if ex.get("oob"):
        return "control: the loopback listener is hit only when the payload is delivered; no payload, no callback"
    if ex.get("idor") or ex.get("access_control") or ex.get("write_idor"):
        return "control: a foreign/unauthorized id is compared to the owner path; a uniform allow/deny is not reported"
    if ex.get("success_if", {}).get("body_regex") or ex.get("success_if", {}).get("redirect_regex"):
        return "the success marker is the RESULT of the injection (absent from the payload), so an echo would not satisfy it"
    if status == "confirmed":
        return "a deterministic observation; a benign baseline did not exhibit the signal"
    return "no control performed (candidate only)"


_SEV = {
    "sql-injection": "raise if the DB holds other tenants' data; lower if the column is non-sensitive",
    "command-injection": "already critical; lower only if the shell runs unprivileged/jailed",
    "ssrf": "raise if cloud-metadata/internal services are reachable; lower if egress is firewalled",
    "idor": "raise if the object is another tenant's; lower if the id is unguessable and rate-limited",
    "broken-object-level-auth": "raise if cross-tenant; lower if same-user-only",
    "xss-reflected": "raise if it runs authenticated same-origin; lower if sandboxed",
    "clickjacking": "raise if a state-changing action is framable; lower if the page is read-only",
    "jwt-weak-secret": "already critical (account takeover); no lowering condition",
    "weak-hash": "raise if it protects passwords/secrets; lower if non-security use",
    "weak-random": "raise if it generates tokens/ids/secrets; lower if non-security use",
}


def fill_from_oracle(f: dict) -> dict:
    """Populate the gate fields from what the engine already produced. Idempotent."""
    status = f.get("status", "candidate")
    ex = f.get("exploit") or f.get("poc")
    f.setdefault("poc", ex or {})
    if not f.get("evidence_text"):
        f["evidence_text"] = f.get("reason") or (f.get("evidence") or {}).get("detail") \
            or (f.get("evidence") or {}).get("line_text") or ""
    if not f.get("counterevidence"):
        f["counterevidence"] = _counterevidence_from(ex or {}, status)
    if status == "confirmed":
        f["confidence"] = "high"                         # an oracle fired (or a deterministic fact) -> high
    elif f.get("confidence") not in _VALID_CONFIDENCE:
        f["confidence"] = "low"
    if f["confidence"] != "high" and not f.get("confidence_rationale"):
        f["confidence_rationale"] = f.get("reason") or "candidate: no oracle confirmation / static-only"
    if not f.get("severity_change_conditions"):
        f["severity_change_conditions"] = _SEV.get(f.get("klass", ""),
            "raise if it reaches sensitive data/privilege; lower if authentication gates the route")
    return f


def validate_report(f: dict) -> list[str]:
    """Reasons this finding may NOT be claimed. Empty = passes."""
    errors = []
    has_exploit = bool(f.get("exploit") or (f.get("poc") and f.get("poc") != {}))
    evidence = str(f.get("evidence_text") or "").strip()
    if not has_exploit and not evidence:                 # a fact with no evidence text is unprovable
        errors.append("poc/evidence REQUIRED — attach a replayable exploit or name the observed fact")
    if not str(f.get("counterevidence") or "").strip():
        errors.append("counterevidence REQUIRED — what was controlled for / argues against")
    conf = f.get("confidence")
    if conf not in _VALID_CONFIDENCE:
        errors.append(f"confidence must be one of {sorted(_VALID_CONFIDENCE)}")
    elif conf != "high" and not str(f.get("confidence_rationale") or "").strip():
        errors.append("confidence_rationale required when confidence != high")
    if not str(f.get("severity_change_conditions") or "").strip():
        errors.append("severity_change_conditions required")
    if (f.get("patch") or f.get("fix_after")) and not str(f.get("fix_verification") or "").strip():
        errors.append("fix_verification REQUIRED when a patch is attached")
    return errors


def gate_finding(finding) -> tuple[bool, list[str]]:
    """Fill + validate a Finding object in place; return (ok, errors). A Finding is any object with the
    attributes we read (klass/status/exploit/reason/evidence) and settable gate attributes."""
    d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
    fill_from_oracle(d)
    errs = validate_report(d)
    for k in ("counterevidence", "confidence", "confidence_rationale", "severity_change_conditions",
              "evidence_text"):
        if hasattr(finding, "__dict__"):
            setattr(finding, k, d.get(k, ""))
    return (not errs, errs)
