"""Slice B of plan 010 — LLM attack-hypothesis generation (parameter + class proposer).

The common "0 findings" cause on a new app is a route we discovered but have no parameter to inject into
(VulnerableApp: 162 of 187 routes). This asks the model, per gap route + its sample response, for the
PARAMETERS it likely reads and the single most likely vuln class for each — then builds CANDIDATE
findings. It does NOT write the oracle: confirmation is done by our existing, sound families via
`confirm_candidates`, so the model fills the param/class gap but never decides what's real (plan 010's
guarantee; precision stays with the deterministic oracle, not an LLM-crafted success check).

Classes restricted to the ones our oracle can actually confirm. Model is an injected `llm(prompt)->str`.
"""
from __future__ import annotations

import json
import re
from typing import Callable

from src.jsauto.findings import Finding

# only classes a deterministic family can confirm (see probes._CLASS_FAMILY)
_ALLOWED = {"sql-injection", "nosql-injection", "command-injection", "path-traversal", "ssrf",
            "open-redirect", "xss"}

_PROMPT = (
    "For the HTTP route below, propose which request PARAMETERS the endpoint reads and, for each, the single "
    "most likely vulnerability class to TEST for (authorized security testing).\n"
    "When HANDLER SOURCE is given, READ IT and use the EXACT parameter names the code reads (e.g. the key "
    "in request.args.get(...), queryParams.get(...), req.query.X, @RequestParam) — do not guess if the code "
    "shows them. Resolve obvious constants to their string value when visible.\n"
    "Output ONLY a JSON array; each item {\"param\":\"name\",\"class\":\"<one of: %s>\"}; at most 4; "
    "de-duplicate; no prose.\n"
    "ROUTE: %s %s\n%sSAMPLE RESPONSE (truncated):\n%s\n"
) % ("|".join(sorted(_ALLOWED)), "%s", "%s", "%s", "%s")


def _extract_array(reply: str):
    for cand in (reply, reply.replace("```json", "```").replace("```", "")):
        m = re.search(r"\[.*\]", cand, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                continue
    return []


def propose_candidates(routes, llm: Callable[[str], str], fetch: Callable[[object], str],
                       source_for: Callable[[object], str] = None, max_routes: int = 25) -> list[Finding]:
    """For gap routes (no params found), ask the model for {param, class}; emit CANDIDATE findings that
    `confirm_candidates` will then try to confirm with the real oracle. When `source_for` returns the
    route's handler code, the model reads the EXACT parameter names from it (source + endpoint together —
    the reliable path on apps that obscure params). Bounded by `max_routes`."""
    out, i, used = [], 0, 0
    for r in routes:
        if r.query_fields or r.path_params or used >= max_routes:   # only routes we have no carrier for
            continue
        used += 1
        try:
            sample = fetch(r)[:2000]
            src = (source_for(r) if source_for else "") or ""
            src_block = f"HANDLER SOURCE (read it for exact param names):\n{src[:6000]}\n" if src else ""
            reply = llm(_PROMPT % (r.method, r.path, src_block, sample))
        except Exception:  # noqa: BLE001 — a model/fetch failure must not sink the run
            continue
        seen = set()
        for item in _extract_array(reply):
            if not isinstance(item, dict):
                continue
            param = str(item.get("param", "")).strip()
            klass = str(item.get("class", "")).strip()
            if not param or klass not in _ALLOWED or (param, klass) in seen:
                continue
            seen.add((param, klass))
            i += 1
            out.append(Finding(
                id=f"LLM-{i:03d}", source="llm", klass=klass, file="(runtime)", status="candidate",
                confidence="low", rule="llm-hypothesis",
                message=f"LLM suspects {klass} via param {param!r} on {r.method} {r.path}",
                evidence={"route": f"{r.method} {r.path}", "param": param}))
    return out


def make_source_lookup(target) -> Callable[[object], str]:
    """A best-effort route->handler-source resolver over a source tree: match a route's most distinctive
    path segment (ignoring LEVEL_n / version / {id} parts) to a source file by name, else by content. Works
    across frameworks where the handler file/class name relates to the route; returns "" when nothing fits.
    Generic — no per-app knowledge."""
    from pathlib import Path
    root = Path(target)
    exts = (".java", ".js", ".ts", ".py", ".rb", ".go", ".php", ".cs")
    files = [p for p in root.rglob("*")
             if p.suffix in exts and "node_modules" not in p.parts and ".git" not in p.parts
             and "test" not in p.name.lower() and p.stat().st_size < 200_000]

    def _segs(path: str) -> list[str]:
        skip = re.compile(r"^(LEVEL_\d+|v\d+|\d+|api|rest)$|^\{.*\}$", re.I)
        return [s for s in path.split("/") if s and not skip.match(s)]

    def lookup(route) -> str:
        segs = _segs(route.path)
        if not segs:
            return ""
        key = segs[-1]
        for p in files:                                  # filename match first (most precise)
            if key.lower() in p.stem.lower():
                return p.read_text(errors="replace")
        for p in files:                                  # fallback: content mentions the segment
            try:
                t = p.read_text(errors="replace")
            except OSError:
                continue
            if key in t:
                return t
        return ""
    return lookup
