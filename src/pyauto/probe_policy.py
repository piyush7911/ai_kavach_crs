"""Pre-probe exclusion policy — decide whether a probe family is worth attempting on a route BEFORE
spending a live request. Runtime verification already makes a false confirmation impossible (a fabricated
exploit simply fails), so this is about not WASTING throttled-probe budget on classes that cannot be
proven, and about respecting the Rules of Engagement (no live DoS). It also records a reason for every
skip, which doubles as the audit trail the RoE require.

The exclusion catalogue is adapted from bug-hunter's Skeptic "hard exclusions" (MIT, © codexstar69),
reframed for a system that confirms over HTTP: some of their static-review exclusions are enforced here
statically, some are already handled by our runtime oracle (noted), and the live-DoS ones we simply never
probe. `allow(klass, route)` returns (attempt?, reason).
"""
from __future__ import annotations

# Classes we never probe live: a proof would be a denial of service, which the RoE forbid. A rate-limit
# check is only ever worth it on sensitive routes (auth / OTP / password-reset / lockout / expensive op),
# and even then as a tiny bounded burst, never a blind flood — so for now these stay inspection-only.
_NO_LIVE_PROBE = {"denial-of-service", "dos", "redos", "rate-limiting", "resource-exhaustion"}

# The catalogue, for the audit record. `enforce`: "static" = checked here; "runtime" = our oracle already
# handles it (a bad exploit just fails); "roe" = excluded by the no-DoS rule.
EXCLUSIONS = [
    ("dos-no-impact", "roe", "DoS / resource exhaustion — a live proof is a denial of service"),
    ("rate-limit-blind", "roe", "rate-limiting — only sensitive routes justify even a bounded burst"),
    ("redos-no-payload", "roe", "ReDoS — a live >1s backtracking payload is a DoS"),
    ("credential-route-not-sqli", "static", "login/register are input-sensitive by design → enumeration/mass-assignment, not SQLi"),
    ("read-no-id-for-exposure", "static", "data-exposure is probed on collection reads, not per-id reads"),
    ("bola-needs-auth-and-id", "static", "object-level authz only applies to an authed route with a resource id in the path"),
    ("enumeration-needs-login", "static", "user-enumeration only applies to a login-shaped route"),
    ("jwt-claim-not-user-input", "runtime", "an id taken from the token (not the URL) is not forgeable → our metamorphic oracle self-excludes"),
    ("opaque-id-not-enumerable", "runtime", "a UUID/ULID path id is not guessable → a substituted id just 404s and self-excludes"),
    ("env-and-flags-trusted", "runtime", "env vars / CLI flags are trusted input, never an HTTP attack surface"),
]


def allow(klass: str, route) -> tuple[bool, str]:
    """(attempt?, reason). The statically-checkable exclusions; the rest are handled at runtime or by RoE."""
    if klass in _NO_LIVE_PROBE:
        return False, "excluded by RoE (no live DoS)"
    carriers = list(route.path_params) + list(route.body_fields) + list(route.query_fields)
    credential = "password" in route.body_fields
    if klass == "excessive-data-exposure":
        if route.method != "GET" or route.path_params:
            return False, "not a collection read"
    elif klass == "injection":
        if not carriers:
            return False, "no input carrier reaches the handler"
        if credential:
            return False, "credential route (login/register) — enumeration, not SQLi"
    elif klass == "broken-object-level-auth":
        if not (route.auth_required and route.path_params):
            return False, "not an authed route with a resource id"
    elif klass == "user-enumeration":
        import re
        if not (route.method == "POST" and credential):
            return False, "not a credential-accepting POST"
        if not re.search(r"log[_-]?in|signin|auth", route.path, re.I):
            return False, "not a login-shaped path"
    return True, "eligible"
