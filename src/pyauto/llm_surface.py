"""Slice A of plan 010 — LLM surface discovery.

When the deterministic discovery leaves a large attack-gap (routes seen but no parameter to inject, or a
SPA whose endpoints aren't in links/sitemap), ask the model to read the app's HTML/JS (and source, when
available) and PROPOSE the endpoints + parameters a client calls. The model only proposes surface; it
never decides a bug — the proposed routes go through the same probes + oracle, so nothing is reported
without a replayed exploit (plan 010's guarantee).

The model is an injected callable `llm(prompt) -> str`, so this is testable without a server; the output
is strictly validated to `{method, path, params}` and turned into `Route`s. Air-gap: the caller wires a
LOCAL model (MODEL_PROBE). Static assets and off-site URLs are dropped.
"""
from __future__ import annotations

import json
import re
from typing import Callable

from src.pyauto.probes import Route

_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
_STATIC = re.compile(r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|js|mjs)(\?|$)", re.I)

_PROMPT = (
    "You are mapping the attack surface of an HTTP application for authorized security testing. From the "
    "HTML/JavaScript (and source, if present) below, list every server endpoint a client calls and the "
    "parameters it sends.\n"
    "Output ONLY a JSON array. Each item: {\"method\":\"GET|POST|PUT|DELETE|PATCH\",\"path\":\"/...\","
    "\"params\":[\"name\",...]}.\n"
    "Rules: same-origin application paths only (must start with '/'); no external URLs; NOT static assets "
    "(.css/.js/.png/...); include query-string and form/JSON field names in params; de-duplicate; at most "
    "%d items; no prose, JSON array only.\n\n%s\n"
)


def _extract_array(reply: str):
    """Pull the first JSON array out of a model reply (tolerates ``` fences and surrounding prose)."""
    for cand in (reply, reply.replace("```json", "```").replace("```", "")):
        m = re.search(r"\[.*\]", cand, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                continue
    return []


def propose_routes(text: str, llm: Callable[[str], str], max_routes: int = 60) -> list[Route]:
    """Ask the model for the app's routes+params from its HTML/JS/source; return validated `Route`s."""
    try:
        reply = llm(_PROMPT % (max_routes, text[:24000]))     # bounded context (~6-8k tokens)
    except Exception:  # noqa: BLE001 — a model failure must not sink the run
        return []
    out, seen = [], set()
    for item in _extract_array(reply):
        if not isinstance(item, dict):
            continue
        method = str(item.get("method", "GET")).upper()
        path = str(item.get("path", "")).strip()
        if method not in _METHODS or not path.startswith("/") or _STATIC.search(path):
            continue
        params = [str(p) for p in (item.get("params") or []) if isinstance(p, (str, int))]
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        out.append(Route(method, path, query_fields=sorted(set(params))))
        if len(out) >= max_routes:
            break
    return out


def gather_surface_text(base_url: str, ctx_path: str = "", max_files: int = 5, max_bytes: int = 40000) -> str:
    """Fetch the homepage + a few same-origin scripts, so the model has the client code that reveals a
    SPA's endpoints. Bounded (files + bytes); purely HTTP, so it needs nothing installed."""
    import urllib.parse
    import urllib.request
    host = urllib.parse.urlparse(base_url).netloc

    def fetch(u):
        try:
            return urllib.request.urlopen(u, timeout=5).read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""
    home = fetch(base_url + ctx_path + "/") or fetch(base_url + "/")
    parts = [f"<!-- page: {ctx_path or '/'} -->\n{home[:max_bytes]}"]
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', home, re.I)[:max_files]:
        u = urllib.parse.urljoin(base_url + ctx_path + "/", src)
        if urllib.parse.urlparse(u).netloc == host and u.split("?")[0].endswith((".js", ".mjs")):
            js = fetch(u)
            if js:
                parts.append(f"<!-- js: {src} -->\n{js[:max_bytes]}")
    return "\n\n".join(parts)
