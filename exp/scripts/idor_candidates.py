"""P3: IDOR/BOLA candidate detection from mined vocab (idor_fields.json) — closes our #1 named gap.

We have no generic IDOR detector (only hand-built two-user oracles per app). This flags a route as an IDOR
CANDIDATE when it takes an object-identifier the attacker controls (a path id segment, or a parameter whose
name matches a known ownership/relationship reference) AND the handler shows no visible ownership check. The
candidate is then handed to the existing two-user metamorphic oracle (_access_control / write-IDOR) for live
confirmation — so a route that actually checks ownership simply never confirms (0 FP; the oracle decides).

Deterministic, framework-agnostic, no LLM. Data: exp/knowledge/idor_fields.json (mined from strix idor.md).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_VOCAB = json.load(open(Path(__file__).resolve().parents[1] / "knowledge" / "idor_fields.json"))
_REF = {n.lower() for n in _VOCAB["ownership_reference_names"]}
_KNOBS = {n.lower() for n in _VOCAB["expansion_projection_knobs"]}
_CHECK_MARKERS = _VOCAB["ownership_check_markers"]
_ID_SEG = re.compile(r"\{(\w+)\}|/:(\w+)")                 # any path-variable segment is an object reference
# a parameter name that denotes an object the attacker references (recall-first; the two-user oracle gates
# precision, so a non-IDOR candidate simply never confirms).
_ID_PARAM = re.compile(r"^(?:id|uuid|guid|slug)$|(?:_id|id)$", re.I)
_RESOURCE_KEYS = {"username", "book_title", "email", "user", "account", "name", "title", "token"}
_LOGIN_RE = re.compile(r"log[_-]?in|signin|register|signup|authenticate|/auth", re.I)
_NON_REF = {"cookietoken", "password", "request", "response", "cookierole", "amount", "csrf", "_csrf"}


def _handler_has_ownership_check(source: str, function: str, window: int = 45) -> bool:
    """True only if an ownership-check marker appears in THIS handler's body (a window after its def), not
    just anywhere in the file — a whole-file check over-suppresses (a JWT import elsewhere would hide a
    genuinely-unprotected BOLA handler). If the function can't be located, do not suppress (recall-first;
    the two-user oracle is the real gate)."""
    if not function:
        return False
    lines = source.splitlines()
    for i, ln in enumerate(lines):
        if re.search(rf"\b{re.escape(function)}\b\s*\(", ln):
            body = "\n".join(lines[i:i + window])
            return any(m in body for m in _CHECK_MARKERS)
    return False


def _id_reason(route: dict) -> str | None:
    """Why this route exposes an attacker-controlled object reference, or None."""
    if _LOGIN_RE.search(route.get("path", "") + " " + route.get("function", "")):
        return None                                    # a login/register route is not a cross-user object read
    params = [p for p in route.get("params", []) if isinstance(p, str) and p.lower() not in _NON_REF]
    for p in params:
        if p.lower() in _REF:
            return f"parameter {p!r} is a known ownership/relationship reference"
        if _ID_PARAM.search(p):
            return f"parameter {p!r} is an object-id reference"
        if p.lower() in _RESOURCE_KEYS:
            return f"parameter {p!r} is a resource key the attacker can point at another user's object"
    for p in params:
        if p.lower() in _KNOBS:
            return f"parameter {p!r} is an expansion/projection knob (can bypass authz in serializers)"
    m = _ID_SEG.search(route.get("path", ""))
    if m:
        seg = next(g for g in m.groups() if g)
        return f"path carries an object reference segment {{{seg}}}"
    return None


def idor_candidates(routes_json: str, source_root: str | None = None) -> list[dict]:
    """Return IDOR candidate dicts {route, method, path, param_or_segment, reason, source_file}. A candidate
    is only raised when the handler shows NO ownership-check marker (best-effort source read)."""
    data = json.load(open(routes_json))
    routes = data.get("routes", data if isinstance(data, list) else [])
    root = Path(source_root) if source_root else None
    srccache: dict[str, str] = {}
    out = []
    for r in routes:
        reason = _id_reason(r)
        if not reason:
            continue
        checked = False
        rel = r.get("file", "")
        if root and rel:
            if rel not in srccache:
                # route-map file paths are relative to a src root; search by basename to be robust
                base = Path(rel).name
                hits = list(root.rglob(base))
                srccache[rel] = hits[0].read_text(errors="replace") if hits else ""
            checked = _handler_has_ownership_check(srccache[rel], r.get("function", ""))
        if checked:
            continue                                   # a visible ownership check -> not a candidate
        out.append({"route": f'{r.get("method","GET")} {r.get("path","")}',
                    "method": r.get("method", "GET"), "path": r.get("path", ""),
                    "reason": reason, "source_file": rel,
                    "note": "no visible ownership check; hand to two-user oracle for live confirmation"})
    return out


def _self_check():
    import tempfile
    rm = {"routes": [
        {"method": "GET", "path": "/api/users/{userId}/profile", "file": "U.java", "params": []},
        {"method": "POST", "path": "/api/transfer", "file": "T.java", "params": ["accountId", "amount"]},
        {"method": "GET", "path": "/api/public/health", "file": "H.java", "params": []},
        {"method": "GET", "path": "/api/report", "file": "R.java", "params": ["fields"]}]}
    d = tempfile.mkdtemp()
    p = Path(d) / "routes.json"
    p.write_text(json.dumps(rm))
    c = idor_candidates(str(p))                        # no source root -> no check suppression
    routes = {x["route"] for x in c}
    assert "GET /api/users/{userId}/profile" in routes          # id path segment
    assert "POST /api/transfer" in routes                       # accountId ref name
    assert "GET /api/report" in routes                          # expansion knob 'fields'
    assert "GET /api/public/health" not in routes               # no id/ref -> not a candidate
    print(f"idor_candidates self-check: OK ({len(c)} candidates)")


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2:
        cs = idor_candidates(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
        print(f"{len(cs)} IDOR candidate(s):")
        for x in cs[:40]:
            print(f"  {x['route']:55} {x['reason']}")
    else:
        _self_check()
