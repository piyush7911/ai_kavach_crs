"""Chunked binary-search parameter discovery (Arjun/x8), promoted from exp. No LLM, language-agnostic.

Finds the HTTP parameters a route actually reads — the #1 recall gap (routes with no injectable param can't
be attacked). Packs many candidate names into ONE request and binary-splits the chunk whose response
differs; ~50-60 requests cover a big dict (vs the old mine_params' thousands). Zero-FP by construction:
each k-name chunk is compared against a same-size JUNK chunk sampled twice, so a response change from mere
param-count or natural jitter cancels — only a change caused by a name the server READS survives. Oracle is
response-diff (status / length-bucket / word-count), not reflection, so it finds un-echoed params too.
"""
from __future__ import annotations

import uuid
from urllib.parse import urlencode

# a focused default wordlist of common web parameter names (framework-agnostic)
_DEFAULT_WORDS = [
    "id", "user", "username", "userid", "uid", "name", "q", "query", "search", "file", "filename", "path",
    "url", "uri", "page", "offset", "limit", "sort", "order", "filter", "type", "category", "action", "cmd",
    "command", "exec", "data", "input", "value", "key", "token", "auth", "session", "email", "password",
    "role", "admin", "account", "accountid", "owner", "ownerid", "tenant", "tenantid", "org", "orgid",
    "project", "projectid", "team", "teamid", "group", "groupid", "parent", "parentid", "target", "dest",
    "redirect", "return", "returnto", "next", "callback", "ref", "referer", "host", "domain", "ip", "address",
    "lang", "locale", "format", "output", "view", "template", "include", "fields", "expand", "select",
    "populate", "with", "per_page", "start", "end", "from", "to", "date", "time", "status", "state", "mode",
    "debug", "test", "env", "config", "option", "comment", "message", "text", "content", "title",
    "description", "body", "subject", "amount", "price", "qty", "quantity", "count", "num", "number", "index",
    "level", "size", "color", "theme", "tag", "label", "code", "hash", "sig", "nonce", "csrf", "xsrf",
    "api_key", "apikey", "secret", "client_id", "scope", "book", "book_title", "product", "product_id",
    "order_id", "invoice_id", "customer_id", "doc", "document", "report", "item", "resource", "resourceid",
    "ipaddress", "ip_address", "hostname", "server", "fileurl", "file_url", "link", "src", "dst", "image",
    "img", "avatar", "upload", "download", "name1", "firstname", "lastname", "phone", "ssn", "dob", "age",
]


def _junk(k):
    return {f"kvj{uuid.uuid4().hex[:6]}": "kvprobe" for _ in range(k)}


def discover(request, names, max_chunk: int = 96, budget: int = 400) -> list[str]:
    """Return the subset of `names` the endpoint reads. `request(params:dict)->(status,body)`. Bounded."""
    counter = [0]
    found: list[str] = []

    def sig(params):
        counter[0] += 1
        status, body = request(params)
        body = body or ""
        return (status, len(body) // 8, len(body.split()))

    def search(chunk):
        if not chunk or counter[0] >= budget:
            return
        base = {sig(_junk(len(chunk))) for _ in range(2)}   # same-size junk, twice (stability)
        if sig({n: "kvprobe" for n in chunk}) in base:
            return                                           # behaves like junk → nothing real here
        if len(chunk) == 1:
            found.append(chunk[0])
            return
        mid = len(chunk) // 2
        search(chunk[:mid])
        search(chunk[mid:])

    for i in range(0, len(names), max_chunk):
        if counter[0] >= budget:
            break
        search(names[i:i + max_chunk])
    return found


def discover_params(base_url, routes, ctx, wordlist=None, budget_per_route: int = 250) -> list:
    """Engine wrapper: for each GET-able route with NO known carrier, discover its query params over HTTP
    (logging in per ctx.auth when the route needs it) and set route.query_fields. Mirrors mine_params'
    contract (routes with params already are skipped) but far faster + finds un-echoed params."""
    from benchmarks.oracles import Session
    from src.pyauto.probes import _fill_path
    wl = wordlist or _DEFAULT_WORDS
    for r in routes:
        if r.query_fields or r.path_params or r.body_fields:
            continue
        sess = Session(base_url, auth=ctx.auth)
        if r.auth_required and ctx.auth:
            try:
                sess.login("user")
            except Exception:  # noqa: BLE001 — a login failure just means we probe unauthenticated
                pass
        path = _fill_path(r.path, {})

        def request(params, _p=path, _s=sess):
            resp = _s.request("GET", _p + ("&" if "?" in _p else "?") + urlencode(params))
            return resp.status, resp.body

        hits = discover(request, wl, budget=budget_per_route)
        if hits:
            r.query_fields = sorted(set(hits))
    return routes
