"""P1: reporting-gate schema for a finding (adapted from strix/tools/reporting/tool.py, Apache-2.0).

Strix refuses to FILE a finding unless it carries proof + a self-critique. Strix asks the LLM to write those
fields; we fill them DETERMINISTICALLY from the oracle (a replayed exploit can't hallucinate its own
counterevidence), then validate. A finding that cannot carry them must not leave `candidate`.

Fields (ours, filled from what the engine already has):
  poc            <- the replayable `exploit` dict               (Strix: poc_script_code, REQUIRED)
  evidence       <- the oracle `reason`/detail                  (Strix: evidence, REQUIRED)
  counterevidence<- what the oracle CONTROLLED for              (Strix: counterevidence, REQUIRED)
  confidence     <- high if confirmed else low                  (Strix: {high,medium,low})
  confidence_rationale <- the gap, when not high                (Strix: required unless high)
  severity_change_conditions <- one line that would move it     (Strix: required)
  fix_verification <- required only when a patch is attached    (Strix: required with fix_after)
"""
from __future__ import annotations

_REQUIRED = ("poc", "evidence", "counterevidence", "confidence", "severity_change_conditions")
_VALID_CONFIDENCE = {"high", "medium", "low"}


def _counterevidence_from(exploit: dict, status: str) -> str:
    """What the oracle checked that argues AGAINST a false positive."""
    ex = exploit or {}
    if ex.get("differential"):
        return ("control: a benign (contradiction) request was sent alongside the attack; the responses "
                "differ only by the injected payload, so reflection alone cannot explain the flip")
    if ex.get("oob"):
        return ("control: our one-time loopback listener is hit ONLY when the payload is delivered; no "
                "callback fires without it, so the finding is not a passive match")
    if ex.get("access_control") or ex.get("idor") or ex.get("write_idor"):
        return ("control: the SAME request as an authorized role is allowed and as an unauthorized role is "
                "the metamorphic comparison; a uniform allow/deny would not have been reported")
    if ex.get("success_if", {}).get("body_regex") or ex.get("success_if", {}).get("redirect_regex"):
        return ("the marker in the success check is the RESULT of the injection (absent from the payload "
                "itself), so a mere echo of the input would not satisfy it")
    if status == "confirmed":
        return "a replayed exploit fired; a benign baseline request did not exhibit the signal"
    return "no control performed (candidate only — not confirmed by an oracle)"


def _severity_conditions_for(klass: str, reachability: str) -> str:
    base = {
        "sql-injection": "raise if the DB holds other tenants' data; lower if the column is non-sensitive",
        "command-injection": "already critical; lower only if the shell runs as an unprivileged, jailed user",
        "ssrf": "raise if cloud metadata/internal services are reachable; lower if egress is firewalled",
        "idor": "raise if the object is another tenant's; lower if the id is unguessable and rate-limited",
        "broken-object-level-auth": "raise if cross-tenant; lower if same-user-only",
        "xss-reflected": "raise if it runs in an authenticated, same-origin context; lower if sandboxed",
        "clickjacking": "raise if a state-changing action is framable; lower if the page is read-only",
        "jwt-weak-secret": "already critical (full account takeover); no lowering condition",
    }.get(klass, "raise if it reaches sensitive data/privilege; lower if authentication gates the route")
    if reachability == "AUTHENTICATED":
        base += " (note: route requires authentication)"
    return base


def fill_from_oracle(f: dict) -> dict:
    """Populate the gate fields from what the engine already produced. Idempotent; never overwrites a
    non-empty field."""
    status = f.get("status", "candidate")
    f.setdefault("poc", f.get("exploit") or f.get("poc") or {})
    if not f.get("evidence_text"):
        f["evidence_text"] = f.get("reason") or (f.get("evidence") or {}).get("detail") or ""
    if not f.get("counterevidence"):
        f["counterevidence"] = _counterevidence_from(f.get("exploit") or {}, status)
    if not f.get("confidence") or f.get("confidence") not in _VALID_CONFIDENCE:
        f["confidence"] = "high" if status == "confirmed" else "low"
    if f["confidence"] != "high" and not f.get("confidence_rationale"):
        f["confidence_rationale"] = f.get("reason") or "candidate: no oracle confirmation / static-only trace"
    if not f.get("severity_change_conditions"):
        f["severity_change_conditions"] = _severity_conditions_for(f.get("klass", ""), f.get("reachability", ""))
    return f


def validate_report(f: dict) -> list[str]:
    """Return the reasons this finding may NOT be filed/promoted. Empty list = passes the gate."""
    errors = []
    poc = f.get("poc") or f.get("exploit")
    if not poc:
        errors.append("poc is REQUIRED — attach the replayable exploit")
    if not str(f.get("evidence_text") or "").strip():
        errors.append("evidence is REQUIRED — the oracle observation that proves it")
    if not str(f.get("counterevidence") or "").strip():
        errors.append("counterevidence is REQUIRED — what was controlled for / argues against")
    conf = f.get("confidence")
    if conf not in _VALID_CONFIDENCE:
        errors.append(f"confidence must be one of {sorted(_VALID_CONFIDENCE)}")
    elif conf != "high" and not str(f.get("confidence_rationale") or "").strip():
        errors.append("confidence_rationale required when confidence != high — name the gap")
    if not str(f.get("severity_change_conditions") or "").strip():
        errors.append("severity_change_conditions required — one thing that would raise/lower severity")
    if (f.get("patch") or f.get("fix_after")) and not str(f.get("fix_verification") or "").strip():
        errors.append("fix_verification REQUIRED when a patch is attached — security closure, bypass "
                      "review, preserved behavior, executed-vs-reasoned")
    return errors


def gate(f: dict) -> tuple[bool, list[str]]:
    """Fill from the oracle, then validate. (ok, errors)."""
    fill_from_oracle(f)
    errs = validate_report(f)
    return (not errs, errs)


def _self_check():
    confirmed = {"klass": "sql-injection", "status": "confirmed",
                 "exploit": {"differential": {"true_request": {"method": "GET", "path": "/x?id=1 OR 1=1"}}},
                 "reason": "injection true≠false (len 114/24)"}
    ok, errs = gate(confirmed)
    assert ok, errs
    assert confirmed["confidence"] == "high" and "control" in confirmed["counterevidence"]
    cand = {"klass": "xss", "status": "candidate"}            # no exploit/evidence
    ok, errs = gate(cand)
    assert not ok and any("poc" in e for e in errs) and cand["confidence"] == "low"
    assert cand["confidence_rationale"]
    patched = dict(confirmed, patch="--- a\n+++ b\n")          # patch but no fix_verification
    ok, errs = gate(patched)
    assert not ok and any("fix_verification" in e for e in errs)
    print("finding_gate self-check: OK")


if __name__ == "__main__":
    _self_check()
