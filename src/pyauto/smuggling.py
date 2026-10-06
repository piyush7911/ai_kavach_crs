"""HTTP request smuggling detector (timing oracle). In scope on an isolated instance.

PortSwigger's timing method: a CL.TE / TE.CL probe makes a desynced back-end wait for bytes that never
arrive, so the response is DELAYED vs a well-formed baseline. Timing is inherently probabilistic — it cannot
be a self-validating proof like a marker or an OOB callback — so, to honor our zero-false-positive CONFIRMED
tier, a smuggling signal is reported as a high-confidence CANDIDATE (never `confirmed`), with the measured
delays as evidence. Jitter is suppressed by requiring the hang on TWO independent trials and a wide margin
over baseline (a calibration knob). Raw sockets (urllib/requests can't send conflicting CL+TE). Bounded,
non-destructive; only safe on an isolated instance (a desync can affect co-tenants sharing the same host).
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from src.jsauto.findings import Finding

_HANG_MARGIN = 5.0          # attack must take >= baseline + this (seconds) on both trials — the calibration knob
_TIMEOUT = 8.0


def _raw_time(host: str, port: int, use_tls: bool, payload: bytes) -> float:
    """Send raw bytes, return seconds until the first response byte (or _TIMEOUT if it hangs)."""
    sock = socket.create_connection((host, port), timeout=_TIMEOUT)
    try:
        if use_tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        t0 = time.time()
        sock.settimeout(_TIMEOUT)
        try:
            sock.recv(1)
            return time.time() - t0
        except socket.timeout:
            return _TIMEOUT
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _clte(path: str, host: str) -> bytes:
    # front-end honors Content-Length (4 = "1\r\nA\r\n"), back-end honors Transfer-Encoding and waits for the
    # next chunk that never comes → hang iff the back-end desyncs on TE.
    body = "1\r\nA\r\nX\r\n"
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n{body}").encode()


def _baseline(path: str, host: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()


def detect_smuggling(base_url: str, paths=None) -> list[Finding]:
    """Timing-probe the target for CL.TE desync; return CANDIDATE findings (timing is not a clean proof).
    A hit requires a baseline round-trip AND the CL.TE probe hanging past baseline+margin on TWO trials."""
    pu = urlparse(base_url)
    host = pu.hostname
    use_tls = pu.scheme == "https"
    port = pu.port or (443 if use_tls else 80)
    paths = paths or [pu.path or "/"]
    out, i = [], 0
    for path in paths:
        try:
            base = min(_raw_time(host, port, use_tls, _baseline(path, host)) for _ in range(2))
            if base >= _TIMEOUT:                        # baseline itself hangs → can't measure, skip (no FP)
                continue
            trials = [_raw_time(host, port, use_tls, _clte(path, host)) for _ in range(2)]
        except OSError:
            continue
        if all(t >= base + _HANG_MARGIN for t in trials):   # both trials hung well past baseline
            i += 1
            out.append(Finding(
                id=f"SMUGGLE-{i:03d}", source="smuggling", status="candidate", confidence="high",
                klass="http-request-smuggling", cwe="CWE-444", file="(runtime)", rule="clte-timing",
                message=f"CL.TE timing desync on {path}: baseline {base:.1f}s vs attack {trials} (margin {_HANG_MARGIN}s)",
                reason="timing oracle (candidate — not a self-validating proof); confirm manually before claiming",
                evidence={"route": f"POST {path}", "baseline_s": round(base, 2), "attack_s": trials,
                          "detail": "CL.TE probe hung on 2/2 trials"}))
    return out
