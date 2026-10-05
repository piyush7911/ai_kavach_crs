"""Sandbox: mode handling everywhere; real denial tests on macOS only."""

import platform
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.patch_validator import sandbox
from src.patch_validator.drv_loop import DRVLoop

DARWIN = platform.system() == "Darwin"


def test_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("KAVACH_SANDBOX", raising=False)
    plan = sandbox.plan("echo hi", tmp_path, {})
    assert not plan.sandboxed and plan.argv == ["/bin/sh", "-c", "echo hi"]


def test_required_without_backend_refuses(monkeypatch, tmp_path):
    monkeypatch.setenv("KAVACH_SANDBOX", "required")
    monkeypatch.setattr(sandbox, "backend", lambda: None)
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.plan("echo hi", tmp_path, {})


def test_required_without_backend_fails_gate(monkeypatch, tmp_path):
    monkeypatch.setenv("KAVACH_SANDBOX", "required")
    monkeypatch.setattr(sandbox, "backend", lambda: None)
    ok, detail = DRVLoop._run("echo hi", "Build", cwd=tmp_path)
    assert not ok and "not run" in detail


def test_auto_without_backend_runs_unsandboxed(monkeypatch, tmp_path):
    monkeypatch.setenv("KAVACH_SANDBOX", "auto")
    monkeypatch.setattr(sandbox, "backend", lambda: None)
    assert not sandbox.plan("echo hi", tmp_path, {}).sandboxed


def test_profile_denies_network_and_writes():
    prof = sandbox.macos_profile(["/private/tmp/ws"])
    assert "(deny network*)" in prof and "(deny file-write*)" in prof
    assert '(subpath "/private/tmp/ws")' in prof


@pytest.mark.skipif(not DARWIN, reason="sandbox-exec is macOS only")
def test_macos_denies_write_outside_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("KAVACH_SANDBOX", "required")
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    ok, _ = DRVLoop._run(f'echo x > "{outside}"', "Build", cwd=ws)
    assert not ok and not outside.exists()
    ok, _ = DRVLoop._run('echo x > inside.txt', "Build", cwd=ws)
    assert ok and (ws / "inside.txt").exists()


@pytest.mark.skipif(not DARWIN, reason="sandbox-exec is macOS only")
def test_macos_denies_network(monkeypatch, tmp_path):
    """
    Denial evidence needs a CONTROL. Asserting only that the connection did not
    succeed passes vacuously when the machine is offline or the script crashes.
    So: the same script must connect when unsandboxed, and be refused by the
    sandbox, with an explicit refusal rather than a timeout or a crash.
    """
    code = ("import socket\ns=socket.socket();s.settimeout(3)\n"
            "try:\n s.connect(('1.1.1.1',53));print('CONNECTED')\n"
            "except OSError as e:\n print('REFUSED', e.errno, e)")
    script = tmp_path / "net.py"
    script.write_text(code)
    cmd = f'"{sys.executable}" "{script}"'

    monkeypatch.setenv("KAVACH_SANDBOX", "off")
    _, control = DRVLoop._run(cmd, "PoV", cwd=tmp_path)
    if "CONNECTED" not in control:
        pytest.skip("no network available to deny, so a denial would prove nothing: " + control.strip()[:80])

    monkeypatch.setenv("KAVACH_SANDBOX", "required")
    _, out = DRVLoop._run(cmd, "PoV", cwd=tmp_path)
    assert "CONNECTED" not in out
    assert "REFUSED" in out, f"expected an explicit refusal, got: {out!r}"


@pytest.mark.skipif(not DARWIN, reason="sandbox-exec is macOS only")
def test_macos_clang_build_works_inside_sandbox(monkeypatch, tmp_path):
    """The point of the sandbox is lost if real gate commands cannot run under it."""
    monkeypatch.setenv("KAVACH_SANDBOX", "required")
    (tmp_path / "a.c").write_text("int main(void){return 0;}\n")
    ok, out = DRVLoop._run('clang -fsanitize=address a.c -o a && ./a', "Build", cwd=tmp_path)
    assert ok, out
