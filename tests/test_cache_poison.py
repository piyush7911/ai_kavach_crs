from types import SimpleNamespace
from src.pyauto.live_probes import _cache_poison


class _L:
    def __init__(self, reflects):
        self.reflects = reflects      # vulnerable cache: victim sees the attacker's unkeyed header value
        self.findings = []
        self._atk_marker = None

    def req(self, method, url, headers=None):
        if headers and ("X-Forwarded-Host" in headers):
            self._atk_marker = headers["X-Forwarded-Host"].split(".")[0]
            return SimpleNamespace(text="poisoned", headers={})
        text = self._atk_marker if self.reflects else "clean"
        return SimpleNamespace(text=text or "clean", headers={})

    def add(self, rid, klass, detail):
        self.findings.append((klass, detail))


def test_cache_poison_confirms_when_victim_sees_marker():
    L = _L(reflects=True)
    _cache_poison(L, "GET /x", "http://x/x", "GET")
    assert L.findings and L.findings[0][0] == "web-cache-poisoning"


def test_cache_poison_silent_when_not_reflected():
    L = _L(reflects=False)
    _cache_poison(L, "GET /x", "http://x/x", "GET")
    assert L.findings == []            # 0 FP


def test_cache_poison_skips_non_get():
    L = _L(reflects=True)
    _cache_poison(L, "POST /x", "http://x/x", "POST")
    assert L.findings == []
