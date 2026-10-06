"""GraphQL attack-surface + BOLA/IDOR candidate generation (T4). Generic, no hardcoding.

A GraphQL BOLA request is byte-identical to a legitimate one, so only multi-identity state detects it — we
already have the two-user oracle. This finds the GraphQL endpoint, runs standard introspection to map the
root queries + their arguments, and emits an IDOR/BOLA CANDIDATE for every query that takes an
object-identifier argument (id / *Id / *_id). Confirmation is the existing two-user replay (query as user A
with an object id, replay as user B — data isolation broken => confirmed); here we produce the surface +
candidates deterministically. Introspection-only, read-only, non-destructive.
"""
from __future__ import annotations

import json

from src.jsauto.findings import Finding

_ENDPOINTS = ["/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/query", "/gql"]
_INTROSPECT = {"query": "{__schema{queryType{name} types{name kind fields{name args{name type{name ofType{name}}}}}}}"}
_ID_ARG = ("id", "uuid", "slug")


def _post(session, path, body):
    try:
        return session.request("POST", path, headers={"Content-Type": "application/json"}, body=body)
    except Exception:  # noqa: BLE001
        return None


def find_graphql(base_url: str, auth: dict | None = None) -> str | None:
    """Return the first path that answers a GraphQL introspection query, else None."""
    from benchmarks.oracles import Session
    for path in _ENDPOINTS:
        s = Session(base_url, auth=auth or {})
        r = _post(s, path, _INTROSPECT)
        if r is not None and r.status == 200 and "__schema" in (r.body or ""):
            return path
    return None


def _query_fields(schema_body: str) -> list[dict]:
    """Parse introspection JSON → the root Query type's fields with their arg names."""
    try:
        data = json.loads(schema_body)["data"]["__schema"]
    except (ValueError, KeyError, TypeError):
        return []
    qname = (data.get("queryType") or {}).get("name") or "Query"
    for t in data.get("types", []):
        if t.get("name") == qname:
            out = []
            for f in (t.get("fields") or []):
                args = [a.get("name", "") for a in (f.get("args") or [])]
                out.append({"field": f.get("name", ""), "args": args})
            return out
    return []


def findings_from_graphql(base_url: str, auth: dict | None = None) -> list[Finding]:
    """Detect GraphQL + emit BOLA/IDOR candidates for object-id-taking root queries."""
    path = find_graphql(base_url, auth)
    if not path:
        return []
    from benchmarks.oracles import Session
    r = _post(Session(base_url, auth=auth or {}), path, _INTROSPECT)
    out, i = [], 0
    for q in _query_fields(r.body if r else ""):
        idargs = [a for a in q["args"] if a.lower() in _ID_ARG or a.lower().endswith("id")]
        if not idargs:
            continue
        i += 1
        out.append(Finding(
            id=f"GQL-{i:03d}", source="graphql", status="candidate", confidence="low",
            klass="broken-object-level-auth", cwe="CWE-639", file="(runtime)", rule="graphql-bola",
            message=f"GraphQL query {q['field']!r} takes object id {idargs} — BOLA candidate (confirm two-user)",
            reason="GraphQL resolver takes an attacker-controlled object id; confirm with a two-user replay",
            evidence={"route": f"POST {path}", "field": q["field"], "id_args": idargs,
                      "detail": "introspection surface; needs two-user data-isolation confirmation"}))
    return out
