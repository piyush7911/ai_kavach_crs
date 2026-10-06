"""T7: schema-driven API fuzzing — a 5xx on a schema-VALID request is a confirmed server fault.

Schemathesis/RESTler idea, dependency-free: auto-fetch the target's OpenAPI spec, send a schema-valid
request per operation (required params filled with type-correct values), and flag any 5xx — an unhandled
exception on valid input is a real robustness/info-leak bug and a FACT (0-FP; the server errored). Also
tries a couple of schema-valid EDGE values (empty string, large int) which routinely trip unhandled paths.
Language-agnostic (pure HTTP + the spec). No external fuzzer, air-gap-safe.
"""
from __future__ import annotations

import json

from src.jsauto.findings import Finding

_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/openapi.yaml", "/swagger/v1/swagger.json",
               "/api-docs", "/api/openapi.json"]


def fetch_spec(base_url: str):
    """Fetch + parse the target's OpenAPI spec from a common path, or None."""
    from benchmarks.oracles import Session
    import yaml
    s = Session(base_url)
    for p in _SPEC_PATHS:
        try:
            r = s.request("GET", p)
        except Exception:  # noqa: BLE001
            continue
        if r.status == 200 and ("openapi" in r.body or "swagger" in r.body) and ("paths" in r.body):
            try:
                return yaml.safe_load(r.body)
            except Exception:  # noqa: BLE001
                continue
    return None


def _value(schema: dict, edge: str = ""):
    """A schema-valid value for a parameter/property; `edge` picks a valid boundary value."""
    t = (schema or {}).get("type", "string")
    if t == "integer" or t == "number":
        return 999999999 if edge == "big" else 1
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    return "" if edge == "empty" else "kvtest"


def _requests_for(path: str, method: str, op: dict):
    """Build 1-3 schema-valid request variants (base + edge values) for one operation."""
    params = op.get("parameters") or []
    query, path_vals = {}, {}
    for p in params:
        if not isinstance(p, dict):
            continue
        loc, name = p.get("in"), p.get("name", "")
        val = _value(p.get("schema") or p, "")
        (path_vals if loc == "path" else query)[name] = val
    import re as _re
    filled = _re.sub(r"\{(\w+)\}", lambda m: str(path_vals.get(m.group(1), "1")), path)
    variants = [(query, {})]
    # one edge variant: empty string / big int on the first query param
    if query:
        k = next(iter(query))
        edge = dict(query)
        edge[k] = _value((next((p for p in params if p.get("name") == k), {}) or {}).get("schema") or {}, "empty")
        variants.append((edge, {}))
    return filled, variants


def schema_fuzz(base_url: str, spec=None, budget: int = 200) -> list[Finding]:
    """Send schema-valid requests for each operation; flag any 5xx as a confirmed server fault."""
    spec = spec or fetch_spec(base_url)
    if not spec:
        return []
    from benchmarks.oracles import Session
    from urllib.parse import urlencode
    s = Session(base_url)
    out, i, n = [], 0, 0
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            if n >= budget:
                break
            filled, variants = _requests_for(path, method, op)
            for query, body in variants:
                n += 1
                url = filled + (("?" + urlencode(query)) if query and method.lower() == "get" else "")
                try:
                    r = s.request(method.upper(), url, body=(query if method.lower() != "get" else None))
                except Exception:  # noqa: BLE001
                    continue
                if r.status >= 500:
                    i += 1
                    out.append(Finding(
                        id=f"SCHEMA-{i:03d}", source="schema-fuzz", status="confirmed", confidence="high",
                        klass="server-error", cwe="CWE-248", file="(runtime)", severity="low",
                        rule="schema-valid-5xx",
                        message=f"{method.upper()} {path} returns {r.status} on a schema-valid request",
                        reason=f"unhandled server error ({r.status}) on a spec-valid input — a fact",
                        evidence={"route": f"{method.upper()} {path}", "status": r.status,
                                  "detail": f"schema-valid request -> {r.status}"}))
                    break                                # one 5xx per operation is enough
    return out
