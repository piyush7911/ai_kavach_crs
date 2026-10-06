"""IDOR/BOLA candidate detection + best-effort confirmation (generic, language-agnostic).

Detection (no LLM): over a framework route map, a route is an IDOR candidate when it exposes an
attacker-controlled object reference (a path id segment; a parameter whose name is a known ownership
reference, an id-suffix, a resource key, or an expansion knob) AND the handler shows no visible ownership
check (function-scoped, so a check elsewhere in the file doesn't hide an unprotected handler). Vocabulary is
mined data (config/idor_fields.json, from strix idor.md). Recall-first — the two-user oracle gates precision.

Confirmation: for a PATH-id route we can confirm without credentials via the direct-object-reference oracle
(request the resource with two different ids; if a foreign id returns DIFFERENT data, the id came from the
URL, not the session). Authenticated/cross-tenant IDOR needs the two-user metamorphic oracle with creds and
is left as a candidate when no auth is configured. A candidate that never confirms stays a candidate — 0 FP.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from src.jsauto.findings import Finding

_VOCAB = json.load(open(Path(__file__).resolve().parents[2] / "config" / "idor_fields.json"))
_REF = {n.lower() for n in _VOCAB["ownership_reference_names"]}
_KNOBS = {n.lower() for n in _VOCAB["expansion_projection_knobs"]}
_CHECK_MARKERS = _VOCAB["ownership_check_markers"]
_ID_SEG = re.compile(r"\{(\w+)\}|/:(\w+)")
_ID_PARAM = re.compile(r"^(?:id|uuid|guid|slug)$|(?:_id|id)$", re.I)
_RESOURCE_KEYS = {"username", "email", "user", "account", "name", "title", "token", "slug"}
_LOGIN_RE = re.compile(r"log[_-]?in|signin|register|signup|authenticate|/auth", re.I)
_NON_REF = {"cookietoken", "password", "request", "response", "cookierole", "amount", "csrf", "_csrf"}


def _handler_has_ownership_check(source: str, function: str, window: int = 45) -> bool:
    if not function:
        return False
    lines = source.splitlines()
    for i, ln in enumerate(lines):
        if re.search(rf"\b{re.escape(function)}\b\s*\(", ln):
            return any(m in "\n".join(lines[i:i + window]) for m in _CHECK_MARKERS)
    return False


def _id_reason(route: dict) -> tuple[str, str] | None:
    """(reason, path-id-segment or '') for an object-reference route, else None."""
    if _LOGIN_RE.search(route.get("path", "") + " " + route.get("function", "")):
        return None
    params = [p for p in route.get("params", []) if isinstance(p, str) and p.lower() not in _NON_REF]
    for p in params:
        if p.lower() in _REF:
            return f"parameter {p!r} is a known ownership/relationship reference", ""
        if _ID_PARAM.search(p):
            return f"parameter {p!r} is an object-id reference", ""
        if p.lower() in _RESOURCE_KEYS:
            return f"parameter {p!r} is a resource key pointing at another user's object", ""
    for p in params:
        if p.lower() in _KNOBS:
            return f"parameter {p!r} is an expansion/projection knob (bypasses authz in serializers)", ""
    m = _ID_SEG.search(route.get("path", ""))
    if m:
        seg = next(g for g in m.groups() if g)
        return f"path carries an object reference segment {{{seg}}}", seg
    return None


def findings_from_idor(routes_json: str, source_root: str | None = None) -> list[Finding]:
    """Emit IDOR/BOLA candidate Findings from a route map."""
    data = json.load(open(routes_json))
    routes = data.get("routes", data if isinstance(data, list) else [])
    root = Path(source_root) if source_root else None
    srccache: dict[str, str] = {}
    out, i = [], 0
    for r in routes:
        res = _id_reason(r)
        if not res:
            continue
        reason, seg = res
        rel = r.get("file", "")
        if root and rel:
            if rel not in srccache:
                hits = list(root.rglob(Path(rel).name))
                srccache[rel] = hits[0].read_text(errors="replace") if hits else ""
            if _handler_has_ownership_check(srccache[rel], r.get("function", "")):
                continue
        i += 1
        method, path = r.get("method", "GET"), r.get("path", "")
        method = method if method in ("GET", "POST", "PUT", "PATCH", "DELETE") else "GET"
        out.append(Finding(
            id=f"IDOR-{i:03d}", source="idor", status="candidate", confidence="low",
            klass="idor", cwe="CWE-639", file=rel, function=r.get("function", ""), rule="idor-vocab",
            message=f"IDOR candidate: {reason}", reason=reason,
            evidence={"route": f"{method} {path}", "id_segment": seg, "reason": reason}))
    return out


def confirm_idor(findings: list[Finding], base_url: str, auth: dict | None = None) -> int:
    """Best-effort confirmation for PATH-id routes via the direct-object-reference oracle: two different ids;
    if the foreign id returns DIFFERENT data, it came from the URL, not the session. Tries unauthenticated
    first (catches no-auth IDOR), then as each configured role (catches authenticated IDOR when creds are
    provided). Promotes on a hit; a candidate that never flips stays a candidate (0 FP). Authenticated IDOR
    with no creds configured, and cross-tenant IDOR with no path id, stay candidates."""
    from benchmarks.oracle_engine import run_exploit
    # roles to try: unauthenticated, then each configured role (or NodeGoat's built-in creds when no spec)
    roles = ["none"] + (sorted((auth or {}).get("roles", {})) if auth else ["user", "admin"])
    promoted = 0
    for f in findings:
        if f.status == "confirmed" or f.klass != "idor":
            continue
        ev = f.evidence or {}
        seg, route = ev.get("id_segment"), ev.get("route", "")
        if not seg or " " not in route:
            continue                                   # only path-id routes are auto-confirmable this way
        method, _, path = route.partition(" ")
        placeholder = f"{{{seg}}}" if f"{{{seg}}}" in path else f":{seg}"   # brace {id} or colon :id form
        done = False
        for role in roles:
            for own, foreign in (("1", "2"), ("2", "1"), ("0", "1"), ("1", "0"), ("1", "3"), ("2", "3")):
                ex = {"idor": {"own_request": {"method": method, "path": path.replace(placeholder, own)},
                               "foreign_request": {"method": method, "path": path.replace(placeholder, foreign)}},
                      "login_as": role, "auth": auth or {}}
                try:
                    hit, detail = run_exploit(base_url, ex)
                except ValueError:                       # role unknown for this app's auth — skip it
                    continue
                if hit:
                    f.status, f.confidence = "confirmed", "high"
                    f.reason = (f"direct object reference (as {role}): foreign id {foreign} returned different "
                                f"data ({detail})")
                    f.exploit = ex
                    promoted += 1
                    done = True
                    break
            if done:
                break
    return promoted
