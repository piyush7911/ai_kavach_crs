"""Positive control for the loopback sandbox (task 1.2).

Under KAVACH_SANDBOX=required the target may reach 127.0.0.1 (its port and the
local DB) but nothing external. Needs sandbox-exec (macOS); skips otherwise.

Run: python -m benchmarks.nodegoat.test_sandbox_loopback   (or pytest)
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from src.patch_validator import sandbox

_NO_BACKEND = sandbox.backend() != "sandbox-exec" or not shutil.which("node")
skip = pytest.mark.skipif(_NO_BACKEND, reason="needs sandbox-exec and node (macOS)")


def _run_node(src: str) -> str:
    os.environ["KAVACH_SANDBOX"] = "required"
    ws = Path(os.environ.get("TMPDIR", "/tmp")) / "kavach_sb_test"
    ws.mkdir(exist_ok=True)
    p = sandbox.plan(f"node -e {subprocess.list2cmdline([src])}", ws, dict(os.environ),
                     allow_loopback=True)
    r = subprocess.run(p.argv, env=p.env, capture_output=True, text=True, timeout=30)
    return (r.stdout + r.stderr).strip()


@skip
def test_external_tcp_denied():
    out = _run_node(
        "const s=require('net').connect({host:'1.1.1.1',port:443},()=>{console.log('OPEN');process.exit(0)});"
        "s.on('error',e=>{console.log('DENIED:'+e.code);process.exit(0)});"
        "setTimeout(()=>{console.log('TIMEOUT');process.exit(0)},5000);")
    assert "DENIED" in out, out  # external must be refused, not opened


@skip
def test_loopback_tcp_allowed():
    # Any listener on loopback proves the policy permits 127.0.0.1; use the Mongo port.
    out = _run_node(
        "const s=require('net').connect({host:'127.0.0.1',port:27017},()=>{console.log('OK');process.exit(0)});"
        "s.on('error',e=>{console.log('FAIL:'+e.code);process.exit(0)});"
        "setTimeout(()=>{console.log('TIMEOUT');process.exit(0)},5000);")
    assert "OK" in out, out  # loopback must connect (Mongo running)


if __name__ == "__main__":
    if _NO_BACKEND:
        print("skip: no sandbox-exec/node")
    else:
        test_external_tcp_denied()
        print("ok  external denied")
        test_loopback_tcp_allowed()
        print("ok  loopback allowed")
