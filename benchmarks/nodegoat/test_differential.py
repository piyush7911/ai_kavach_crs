"""Offline check for the boolean-based-injection oracle's normalizer (no server)."""
from benchmarks.nodegoat.exploit import _norm


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
