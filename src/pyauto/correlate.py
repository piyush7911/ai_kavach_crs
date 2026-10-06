"""Correlate source-level candidates (static / Opengrep taint / a scanner's code-location alert) to the
discovered HTTP routes, so our oracle can CONFIRM them.

A static candidate names a file + function + class; the oracle needs a route + param. This joins the two:
for each candidate with a code location, find the discovered route whose handler is that candidate's
file/function. Matching, best-effort and framework-agnostic:
  1. operationId/handler identity, when the route carries one (route_to_source);
  2. the candidate's file STEM appears as a route path segment (controller-named routes, e.g.
     ErrorBasedSQLInjectionVulnerability.java -> /ErrorBasedSQLInjectionVulnerability/LEVEL_1);
  3. the candidate's function name appears in a route path.
A correlated candidate gets `evidence.route` set; the param is filled from the taint source if present,
else left for the LLM proposer (Slice B.5) to read from the handler source. Then `confirm_candidates`
replays it. Nothing becomes `confirmed` without that replay — correlation only makes a candidate testable.
"""
from __future__ import annotations

import re

from src.pyauto.probes import route_to_source


def _route_str(route) -> str:
    return f"{route.method} {route.path}"


def correlate(candidates: list, routes: list) -> list:
    """Attach `evidence.route` (+ carry the taint param) to each code-location candidate that maps to a
    discovered route. Returns the candidates that became route-bound (ready for confirmation)."""
    # index routes by handler identity and by lowercased path, for the three match strategies
    by_handler = {}
    for r in routes:
        src = route_to_source(getattr(r, "operation_id", "") or "")
        if src:
            by_handler[(src["file"], src["function"])] = r
    bound = []
    for c in candidates:
        if (c.evidence or {}).get("route"):          # already route-bound (e.g. a probe finding)
            continue
        cfile, cfunc = c.file or "", c.function or ""
        match = None
        # 1. exact handler identity
        if cfile and cfunc and (cfile, cfunc) in by_handler:
            match = by_handler[(cfile, cfunc)]
        if match is None:                            # 2/3. file stem or function name as a path segment
            stem = re.sub(r"\.[^.]+$", "", cfile.split("/")[-1]) if cfile else ""
            needles = [n for n in (stem, cfunc) if n and len(n) > 3]
            for r in routes:
                segs = [s.lower() for s in r.path.split("/") if s]
                if any(n.lower() in segs or any(n.lower() in s for s in segs) for n in needles):
                    match = r
                    break
        if match is None:
            continue
        c.evidence = {**(c.evidence or {}), "route": _route_str(match), "correlated_from": f"{cfile}:{cfunc}"}
        bound.append(c)
    return bound
