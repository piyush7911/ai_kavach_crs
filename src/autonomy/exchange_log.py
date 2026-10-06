"""Independent HTTP exchange log.

Without this, a finding's evidence is whatever the oracle code asserts happened. This module makes that
auditable: every request the oracle sends is appended to an append-only log with a numeric id; a finding
cites the ids it used; verify() rejects any id absent from the log. No external proxy needed (a
self-contained logger) — air-gap-safe. Turns "confirmed by a live exploit" into an independently
queryable claim instead of a trusted code-path assertion.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path


class ExchangeLog:
    """Append-only numeric-id log of HTTP exchanges the oracle actually sent."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._n = 0
        self._lock = threading.Lock()
        self.path.write_text("")                       # fresh per run

    def record(self, method: str, url: str, status: int, req: dict | None = None,
               resp_preview: str = "") -> str:
        """Log one exchange; return its id (a numeric string)."""
        with self._lock:
            self._n += 1
            rid = str(self._n)
            row = {"id": rid, "method": method, "url": url, "status": status,
                   "request": req or {}, "response_preview": (resp_preview or "")[:500]}
            with self.path.open("a") as f:
                f.write(json.dumps(row, default=str) + "\n")
            return rid


def load_ids(path: str) -> set[str]:
    """The set of exchange ids the log actually recorded."""
    ids = set()
    p = Path(path)
    if not p.exists():
        return ids
    for line in p.read_text(errors="replace").splitlines():
        try:
            ids.add(str(json.loads(line)["id"]))
        except (ValueError, KeyError):
            continue
    return ids


def verify(cited_ids, log_path: str) -> tuple[list[str], list[str]]:
    """Split cited ids into (known, rejected) against the log. A finding citing a rejected id must not be
    filed on that evidence — the exchange was never independently recorded."""
    have = load_ids(log_path)
    known = [i for i in map(str, cited_ids or []) if i in have]
    rejected = [i for i in map(str, cited_ids or []) if i not in have]
    return known, rejected


def _self_check():
    import tempfile
    log = str(Path(tempfile.mkdtemp()) / "exchanges.jsonl")
    xl = ExchangeLog(log)
    a = xl.record("GET", "http://x/a?id=1 OR 1=1", 200, resp_preview="2 rows")
    b = xl.record("GET", "http://x/a?id=1 AND 1=2", 200, resp_preview="0 rows")
    assert a == "1" and b == "2"
    known, rejected = verify([a, b, "999"], log)
    assert known == ["1", "2"] and rejected == ["999"]     # fabricated id 999 is rejected
    assert load_ids(log) == {"1", "2"}
    print("exchange_log self-check: OK")


if __name__ == "__main__":
    _self_check()
