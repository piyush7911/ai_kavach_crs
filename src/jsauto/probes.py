"""
Turn a finding into a replayable exploit request, in the language-neutral format both tracks share:

    {"method", "path", "headers"?, "body"?, "login_as", "follow_redirects"?, "success_if": {...}}

Nothing here sends a request. It only DESCRIBES one; the runner's `replay` sends it against an instance
started for the purpose, over loopback, throttled. Keeping description and execution apart is what lets
this be tested without an application and keeps the probing within the rules (our own instance only).

How the request is built, all from the finding's evidence and never from an application's names:

  * where the user data enters: the route (method, path) of the entry point, and the request property and
    field the tainted expression reads (`<req>.query.url` -> query parameter `url`; `.body.x` -> form
    field `x`; `.params.id` -> a path segment);
  * what to send: a payload per vulnerability class from config/js_probes.json, with an oracle that can
    be checked from the response alone;
  * every OTHER request field the same expression needs gets a benign value, so the handler reaches the
    vulnerable line instead of rejecting an incomplete request.

A class whose oracle does not fit the contract is reported as unsupported with the reason.
"""

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlencode

PROBES_PATH = Path(__file__).resolve().parents[2] / "config" / "js_probes.json"
_FIELD = re.compile(r"\b[A-Za-z_$][\w$]*\.(query|body|params|payload|headers|cookies)\.([A-Za-z_$][\w$]*)")
_LOCATIONS = {"query", "body", "params", "payload"}


def load_probes(path: Path = PROBES_PATH) -> dict:
    return json.loads(Path(path).read_text())


def input_fields(tainted_expr: str) -> list[tuple[str, str]]:
    """[(location, field)] read by the tainted expression, in order, without repeats."""
    seen, out = set(), []
    for m in _FIELD.finditer(tainted_expr or ""):
        key = (m.group(1), m.group(2))
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _fill_path(route_path: str, params: dict) -> str:
    """Substitute `:name` and `${name}` path parameters; unknown ones get the benign value."""
    def sub(m):
        name = m.group(1) or m.group(2)
        return quote(str(params.get(name, params["_benign"])), safe="")
    return re.sub(r":([A-Za-z_]\w*)|\$\{(\w+)\}", sub, route_path)


def exploit_for(finding: dict, oob_url: str = "{OOB}", probes: Optional[dict] = None) -> tuple[Optional[dict], str]:
    """
    (exploit, note). `exploit` is None when no probe can be built, and `note` says why. When it is built,
    `note` records which input carries the payload.
    """
    probes = probes or load_probes()
    klass = finding.get("klass", "")
    if klass in probes["unsupported"]:
        return None, probes["unsupported"][klass]
    spec = probes["classes"].get(klass)
    if spec is None:
        return None, f"no probe is defined for class {klass!r}"
    ev = finding.get("evidence") or {}
    route = (ev.get("entry") or {}).get("route")
    if not route:
        return None, "the entry point has no route, so there is no request to send"
    fields = input_fields(ev.get("tainted_expr", ""))
    carriers = [f for f in fields if f[0] in _LOCATIONS]
    if not carriers:
        return None, "the tainted expression does not name a query, body or path field"

    benign = probes.get("benign_value", "1")
    payload = spec["value"].replace("{OOB}", oob_url)
    carrier = carriers[0]                                     # the first field is the one given the payload
    values = {f[1]: (payload if f == carrier else benign) for f in carriers}
    success = dict(spec["success_if"])

    method = (route.get("method") or "GET").upper()
    if method == "ALL":
        method = "GET"
    path = _fill_path(route["path"], {**values, "_benign": benign})
    exploit: dict = {"method": method, "login_as": "user"}
    query = {n: v for (loc, n), v in zip(carriers, [values[c[1]] for c in carriers]) if loc == "query"}
    body = {n: v for (loc, n), v in zip(carriers, [values[c[1]] for c in carriers]) if loc in ("body", "payload")}
    if query:
        path += ("&" if "?" in path else "?") + urlencode(query)
    exploit["path"] = path
    if body:
        exploit["body"] = body
        exploit["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
    if spec.get("follow_redirects") is False:
        exploit["follow_redirects"] = False
    exploit["success_if"] = success
    where = f"{carrier[0]}.{carrier[1]}"
    return exploit, f"payload carried by {where}; other fields get a benign value"


def attach(findings: list, oob_url: str = "{OOB}") -> dict:
    """Fill `exploit` on every finding that has a buildable probe. Returns {finding id: note}."""
    probes = load_probes()
    notes = {}
    for f in findings:
        d = f if isinstance(f, dict) else f.to_dict()
        exploit, note = exploit_for(d, oob_url, probes)
        notes[d["id"]] = note
        if exploit is not None:
            if isinstance(f, dict):
                f["exploit"] = exploit
            else:
                f.exploit = exploit
    return notes
