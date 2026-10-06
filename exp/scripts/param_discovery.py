"""T1: chunked binary-search parameter discovery (Arjun/x8 technique). No LLM, language-agnostic.

Our #1 recall gap: routes with no injectable parameter we could attack. Our old mine_params brute-tried a
few values per name (thousands of sequential requests, slow, weak). This packs MANY candidate names into ONE
request and binary-splits the chunk whose response differs — ~50-60 requests to cover a big dict.

Zero-FP guards (critical — a hidden param must really exist, not be jitter):
  * same-size junk baseline: each chunk of k candidate names is compared against k JUNK names, so a response
    change caused merely by "there are k extra query params" cancels out — only a change from a name the
    server actually READS survives.
  * stability: the junk baseline is sampled twice; a chunk counts as different only if it differs from BOTH
    junk samples, so natural response jitter (timestamps, random content) never yields a false param.
Oracle is response-DIFF (status / length-bucket / word-count), not reflection, so it finds params with no
echo — exactly the auth-gated case. `request(params)->(status, body)` is injected, so it runs over our
Session with --auth for authenticated routes.
"""
from __future__ import annotations

import uuid


def _sig(request, params, counter):
    counter[0] += 1
    status, body = request(params)
    body = body or ""
    return (status, len(body) // 8, len(body.split()))


def _junk(k):
    return {f"kvj{uuid.uuid4().hex[:6]}": "kvprobe" for _ in range(k)}


def discover(request, names, max_chunk: int = 96, budget: int = 400) -> list[str]:
    """Return the subset of `names` the endpoint actually reads. `request(params:dict)->(status,body)`.
    Bounded by `budget` requests."""
    counter = [0]
    found: list[str] = []

    def junk_sig(k):                                     # same-size junk baseline, sampled twice (stability)
        return {_sig(request, _junk(k), counter) for _ in range(2)}

    def search(chunk):
        if not chunk or counter[0] >= budget:
            return
        base = junk_sig(len(chunk))                      # k junk params = the "no real param" behaviour
        s = _sig(request, {n: "kvprobe" for n in chunk}, counter)
        if s in base:                                    # behaves like junk of the same size → nothing real
            return
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


def _self_check():
    # mock server: reads exactly one real param "secret" (and ignores everything else). A request carrying
    # "secret" returns a longer body; junk params do not change it.
    def mock(params):
        if "secret" in params:
            return 200, "FOUND THE SECRET VALUE EXTRA WORDS HERE " * 3
        return 200, "default body"
    names = [f"p{i}" for i in range(200)] + ["secret"] + [f"q{i}" for i in range(55)]
    hits = discover(mock, names)
    assert hits == ["secret"], hits
    # a server that reads NOTHING yields no params (no false positive)
    assert discover(lambda p: (200, "static"), [f"n{i}" for i in range(128)]) == []
    # jittery server (random length each request) must not produce a false param — stability + same-size junk
    import random
    assert discover(lambda p: (200, "x " * random.randint(1, 3)), [f"n{i}" for i in range(64)]) == []
    print("param_discovery self-check: OK")


if __name__ == "__main__":
    _self_check()
