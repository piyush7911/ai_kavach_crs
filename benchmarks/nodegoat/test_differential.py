"""Offline check for the boolean-based-injection oracle's normalizer (no server)."""
from benchmarks.oracle_engine import _norm


def test_norm_strips_volatile_values():
    # Random seed numbers / ids must not count as a difference; structure must.
    a = "<strong>33 %</strong><strong>7 %</strong>"
    b = "<strong>5 %</strong><strong>91 %</strong>"
    assert _norm(a) == _norm(b)                 # same structure, different numbers → equal


def test_norm_keeps_structural_difference():
    rows = "<strong> %</strong><strong> %</strong>"
    error = "No allocations found"
    assert _norm(rows) != _norm(error)          # rows vs error page → different


if __name__ == "__main__":
    test_norm_strips_volatile_values(); print("ok norm strips volatile")
    test_norm_keeps_structural_difference(); print("ok norm keeps structure")
    print("all passed")


def test_denied_recognises_refusals_and_serves():
    from benchmarks.oracle_engine import _denied, Response
    assert _denied(Response(403, "", ""))                       # forbidden
    assert _denied(Response(302, "", "/login"))                 # bounced to login
    assert _denied(Response(302, "", "/dashboard"))             # bounced to landing
    assert not _denied(Response(200, "ok", ""))                 # served
    assert not _denied(Response(302, "", "/benefits"))          # redirect to the resource itself = served
