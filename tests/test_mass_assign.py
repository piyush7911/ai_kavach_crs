from types import SimpleNamespace
from src.pyauto.live_probes import _mass_assign


class _FakeL:
    """A vulnerable server: it stores whatever body is written and echoes it on GET."""
    def __init__(self, vulnerable=True):
        self.stored = ""
        self.vulnerable = vulnerable
        self.findings = []

    def req(self, method, url, **kw):
        if method == "GET":
            return SimpleNamespace(text=self.stored, status_code=200)
        body = kw.get("json") or kw.get("data") or {}
        if self.vulnerable:                              # accepts unspecified fields -> echoes them back
            self.stored = str(body)
        return SimpleNamespace(text="ok", status_code=200)

    def add(self, rid, klass, detail):
        self.findings.append((klass, detail))


def test_mass_assign_confirms_when_privileged_field_persists():
    L = _FakeL(vulnerable=True)
    _mass_assign(L, "PUT /users/1", {"body": True}, "/users/1", "PUT")
    assert L.findings and L.findings[0][0] == "mass-assignment"


def test_mass_assign_silent_when_field_rejected():
    L = _FakeL(vulnerable=False)                         # server ignores the extra field -> read-back clean
    _mass_assign(L, "PUT /users/1", {"body": True}, "/users/1", "PUT")
    assert L.findings == []                              # 0 FP


def test_mass_assign_skips_get_routes():
    L = _FakeL()
    _mass_assign(L, "GET /x", {}, "/x", "GET")
    assert L.findings == []
