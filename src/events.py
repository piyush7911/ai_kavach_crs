"""
AI Kavach CRS — structured run events.

One line of JSON per event, appended to a file. The benchmark harness, the
autonomous mode and the dashboard all use the same vocabulary, so a viewer can
show a live run without scraping coloured console output.

Rules
-----
* An event records something that **happened**. Nothing here synthesises,
  replays or pads events: a consumer that shows a timeline is showing the run.
* A sink with no path is a no-op, so instrumented code needs no `if events:`
  guards and costs nothing when nobody is listening.
* Writes are serialised and flushed per line. Agents run in threads, and a
  reader tailing the file must never see half a line.

Event shape::

    {"ts": 1759300000.12, "seq": 17, "kind": "target_done",
     "stage": "verify", "status": "pass", "message": "...", "data": {...}}

`kind` is the event type; `stage` and `status` are optional and describe the
pipeline position and outcome. `data` carries structured detail.
"""

import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

# Statuses a consumer may rely on. Anything else is shown verbatim.
STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"
STATUS_INFO = "info"


class EventSink:
    """Append-only JSONL event writer. Safe to share across threads."""

    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._seq = 0
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Truncate: a sink owns its file for one run.
            self.path.write_text("")

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def emit(
        self,
        kind: str,
        *,
        stage: str = "",
        status: str = "",
        message: str = "",
        **data: Any,
    ) -> None:
        if not self.path:
            return
        with self._lock:
            self._seq += 1
            event = {
                "ts": round(time.time(), 3),
                "seq": self._seq,
                "kind": kind,
                "stage": stage,
                "status": status,
                "message": message,
                "data": data,
            }
            # default=str: a Path or Enum in `data` must not lose the event.
            with open(self.path, "a") as f:
                f.write(json.dumps(event, default=str) + "\n")
                f.flush()


def read_events(path: str | Path, after_seq: int = 0) -> list[dict]:
    """Events with seq > after_seq. Tolerates a trailing partial line."""
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue          # a line still being written; the next poll gets it
        if event.get("seq", 0) > after_seq:
            out.append(event)
    return out


NULL_SINK = EventSink(None)
