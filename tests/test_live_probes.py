import pytest
from src.pyauto.live_probes import live_confirm, _collapse, _GLOBAL
from src.jsauto.findings import Finding


def test_refuses_non_loopback():
    with pytest.raises(ValueError):
        live_confirm("http://evil.example", [], ctx="")


def _f(klass, route):
    return Finding(id=f"{klass}:{route}", source="live", klass=klass, file="(runtime)",
                   status="confirmed", evidence={"route": route})


def test_collapse_global_once_perroute_kept():
    fs = [_f("clickjacking", "GET /a"), _f("clickjacking", "GET /b"), _f("clickjacking", "GET /c"),
          _f("xss-reflected", "GET /x"), _f("xss-reflected", "GET /y")]
    out = _collapse(fs)
    klasses = [f.klass for f in out]
    assert klasses.count("clickjacking") == 1          # app-global collapsed to one
    assert klasses.count("xss-reflected") == 2         # per-route kept
    cj = next(f for f in out if f.klass == "clickjacking")
    assert cj.evidence["affected_routes"] == 3 and "3 routes" in cj.message


def test_global_set_has_header_classes():
    assert {"clickjacking", "cookie-flags", "cors-misconfig", "jwt-weak-secret"} <= _GLOBAL
