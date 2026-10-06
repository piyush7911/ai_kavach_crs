"""Evidenced coverage ledger.

Findings answer "what did we find". Coverage answers "what did we look at, and how did each close" — the
negative space that makes "zero findings" trustworthy. Each (surface, risk_area) pair gets ONE evidenced
outcome. Turns the count-based probes.coverage() into a checkable per-(route,class) record.

Outcomes: reported | no_issue_found | ruled_out | not_applicable | needs_follow_up.
Evidence is MANDATORY for ruled_out / not_applicable / needs_follow_up.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

VALID_OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up")
_EVIDENCE_REQUIRED = {"ruled_out", "not_applicable", "needs_follow_up"}


def _norm(outcome: str) -> str:
    return outcome.strip().lower().replace("-", "_").replace(" ", "_")


class CoverageLedger:
    """A set of coverage entries, deduped on (surface, risk_area) case-insensitively."""

    def __init__(self):
        self._by_key: dict[tuple, dict] = {}

    def record(self, surface: str, risk_area: str, outcome: str, evidence: str = "") -> list[str]:
        """Add an entry. Returns validation errors ([] = stored)."""
        outcome = _norm(outcome)
        errors = []
        if not surface.strip():
            errors.append("surface cannot be empty — name the route/file/component")
        if not risk_area.strip():
            errors.append("risk_area cannot be empty — name what you tested for")
        if outcome not in VALID_OUTCOMES:
            errors.append(f"invalid outcome {outcome!r}; must be one of {list(VALID_OUTCOMES)}")
        if outcome in _EVIDENCE_REQUIRED and not evidence.strip():
            errors.append(f"evidence is required for outcome '{outcome}'")
        if errors:
            return errors
        key = (surface.strip().lower(), risk_area.strip().lower())
        self._by_key.setdefault(key, {
            "surface": surface.strip(), "risk_area": risk_area.strip(), "outcome": outcome,
            "evidence": evidence.strip(),
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")})
        return []

    def entries(self) -> list[dict]:
        return sorted(self._by_key.values(), key=lambda e: e["created_at"])

    def counts(self) -> dict:
        c = {}
        for e in self._by_key.values():
            c[e["outcome"]] = c.get(e["outcome"], 0) + 1
        return {o: c[o] for o in VALID_OUTCOMES if o in c}

    def dump(self, path: str) -> None:
        json.dump({"entries": self.entries(), "outcome_counts": self.counts()},
                  open(path, "w"), indent=1, default=str)


# classes an oracle can actively confirm (so a param-less attacked route is "needs_follow_up", not clean)
_ORACLE_CLASSES = {"sql-injection", "nosql-injection", "command-injection", "path-traversal", "ssrf",
                   "open-redirect", "xss", "xxe", "insecure-deserialization", "idor",
                   "broken-object-level-auth"}


def ledger_from_run(routes, findings, probe_classes=None) -> CoverageLedger:
    """Build a ledger from a dynamic run: every route gets an evidenced outcome per probed class.
    `routes` are Route objects; `findings` the confirmed/candidate list; `probe_classes` the classes we try
    (defaults to the oracle set)."""
    probe_classes = probe_classes or sorted(_ORACLE_CLASSES)
    L = CoverageLedger()
    confirmed = {(f.klass, (f.evidence or {}).get("route")) for f in findings
                 if getattr(f, "status", "") == "confirmed"}
    for r in routes:
        rid = f"{r.method} {r.path}"
        has_param = bool(getattr(r, "path_params", None) or getattr(r, "query_fields", None)
                         or getattr(r, "body_fields", None))
        for klass in probe_classes:
            if (klass, rid) in confirmed:
                L.record(rid, klass, "reported", "confirmed by a replayed exploit")
            elif not has_param:
                L.record(rid, klass, "needs_follow_up",
                         "no injectable parameter discovered on this route; not actively testable yet")
            else:
                L.record(rid, klass, "no_issue_found",
                         f"{klass} payloads sent to this route's parameters; oracle did not fire")
    return L


def _self_check():
    L = CoverageLedger()
    assert L.record("GET /a", "sql-injection", "reported", "exploit fired") == []
    # dedupe: same (surface, risk_area) ignored on second record
    L.record("GET /a", "sql-injection", "no_issue_found", "x")
    assert len(L.entries()) == 1 and L.entries()[0]["outcome"] == "reported"
    # evidence required for ruled_out
    errs = L.record("GET /b", "xxe", "not_applicable", "")
    assert errs and "evidence is required" in errs[0]
    assert L.record("GET /b", "xxe", "not_applicable", "no XML parsing on this route") == []
    # normalization
    assert L.record("GET /c", "ssrf", "Needs-Follow-Up", "no egress to test") == []
    assert L.counts()["needs_follow_up"] == 1
    print("coverage_ledger self-check: OK", L.counts())


if __name__ == "__main__":
    _self_check()
