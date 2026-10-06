"""Pure-logic checks for the benchmark harness scoring (no live target)."""
from types import SimpleNamespace as NS

from benchmarks.bench import _jaccard, _match, _score_run


def _f(klass, route):
    return NS(klass=klass, evidence={"route": f"GET {route}"})


LABELS = [
    {"id": "sqli", "klass": "injection", "route": "/users/v1/{username}", "severity": "critical", "discovery": "dynamic"},
    {"id": "enum", "klass": "user-enumeration", "route": "/users/v1/login", "severity": "medium", "discovery": "dynamic"},
    {"id": "jwt", "klass": "weak-jwt", "route": "config.py", "severity": "high", "discovery": "static"},
    {"id": "rl", "klass": "rate-limiting", "route": "*", "severity": "medium", "discovery": "roe_excluded"},
]


def test_match_route_and_class():
    assert _match(_f("injection", "/users/v1/{username}"), LABELS[0])
    assert not _match(_f("injection", "/books/v1"), LABELS[0])       # wrong route
    assert not _match(_f("user-enumeration", "/users/v1/{username}"), LABELS[0])  # wrong class


def test_recall_only_counts_in_scope_labels():
    # found both dynamic bugs; static + roe labels are NOT counted against recall
    findings = [_f("injection", "/users/v1/{username}"), _f("user-enumeration", "/users/v1/login")]
    s = _score_run(findings, LABELS)
    assert s["recall"] == 1.0 and s["precision"] == 1.0 and s["f1"] == 1.0


def test_partial_recall_and_severity_weight():
    findings = [_f("user-enumeration", "/users/v1/login")]   # missed the critical sqli
    s = _score_run(findings, LABELS)
    assert s["recall"] == 0.5                                 # 1 of 2 in-scope
    # severity-weighted recall is lower: caught medium(2) of medium(2)+critical(8)
    assert s["severity_weighted_recall"] == round(2 / 10, 3)


def test_jaccard():
    assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert _jaccard({"a", "b"}, {"a"}) == 0.5
    assert _jaccard(set(), set()) == 1.0
