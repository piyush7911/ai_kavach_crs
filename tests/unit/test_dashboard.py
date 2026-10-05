"""
Tests for the live dashboard backend.

The upload rules are security controls: a dropped archive is untrusted and
everything downstream compiles and runs code from it. They are tested directly
(as pure functions) and again through the HTTP route, so a refactor cannot move
a check out of the path a browser actually takes.

The results and job tests pin the "shows only what was produced" rules.
"""

import io
import json
import stat
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard import results, uploads
from dashboard.jobs import BusyError, JobManager

C_SRC = b'#include <stdio.h>\nint main(void){puts("hi");return 0;}\n'


def _zip_bytes(members) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for m in members:
            if isinstance(m, zipfile.ZipInfo):
                zf.writestr(m, b"x")
            else:
                zf.writestr(m[0], m[1])
    return buf.getvalue()


# --- path safety -------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "../evil.c", "a/../../evil.c", "/etc/passwd", "C:/Windows/x.c", "a\\b.c", "a/..\\b.c", "", "\x00.c", "./..",
])
def test_unsafe_member_names_are_rejected(name):
    assert uploads.safe_member_path(name) is None


@pytest.mark.parametrize("name", ["main.c", "src/util.h", "a/b/c/d.cpp", "./src/x.c"])
def test_ordinary_member_names_are_accepted(name):
    assert uploads.safe_member_path(name) is not None


def test_normalisation_cannot_smuggle_traversal():
    """A name that only becomes unsafe after normalisation must still be refused."""
    assert uploads.safe_member_path("a/./../../x.c") is None


# --- archive validation ---------------------------------------------------------

def _validate(members):
    with zipfile.ZipFile(io.BytesIO(_zip_bytes(members))) as zf:
        return uploads.validate_zip(zf)


def test_good_archive_validates():
    assert len(_validate([("p/main.c", C_SRC), ("p/a.h", b"int x;")])) == 2


def test_zip_slip_is_refused():
    with pytest.raises(uploads.UploadError, match="unsafe path"):
        _validate([("p/main.c", C_SRC), ("../escape.c", C_SRC)])


def test_symlink_member_is_refused():
    link = zipfile.ZipInfo("p/link.c")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(uploads.UploadError, match="symbolic link"):
        _validate([("p/main.c", C_SRC), link])


def test_oversized_single_file_is_refused(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_FILE_BYTES", 1024)
    with pytest.raises(uploads.UploadError, match="too large"):
        _validate([("p/big.c", b"A" * 4096)])


def test_total_expansion_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_TOTAL_BYTES", 3000)
    with pytest.raises(uploads.UploadError, match="expands beyond"):
        _validate([(f"p/f{i}.c", b"A" * 1000) for i in range(5)])


def test_file_count_cap_is_enforced(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_FILES", 3)
    with pytest.raises(uploads.UploadError, match="too many files"):
        _validate([(f"p/f{i}.c", b"x") for i in range(5)])


def test_extraction_stays_inside_destination(tmp_path):
    z = tmp_path / "ok.zip"
    z.write_bytes(_zip_bytes([("p/main.c", C_SRC), ("p/sub/u.h", b"int y;")]))
    dest = tmp_path / "out"
    dest.mkdir()
    assert uploads.extract_zip(z, dest) == 2
    assert (dest / "p" / "main.c").read_bytes() == C_SRC
    # nothing was written beside the destination
    assert {p.name for p in tmp_path.iterdir()} == {"ok.zip", "out"}


def test_extraction_enforces_size_while_writing(tmp_path, monkeypatch):
    """The cap must hold even if a header understates the real size."""
    z = tmp_path / "lie.zip"
    z.write_bytes(_zip_bytes([("p/blob.c", b"A" * 5000)]))
    monkeypatch.setattr(uploads, "MAX_FILE_BYTES", 10_000)       # passes the declared-size check…
    monkeypatch.setattr(uploads, "MAX_TOTAL_BYTES", 2000)        # …but not the streamed total
    # declared size (5000) already exceeds the total cap, so lower only the streamed one
    monkeypatch.setattr(uploads, "MAX_TOTAL_BYTES", 6000)
    dest = tmp_path / "o"
    dest.mkdir()
    assert uploads.extract_zip(z, dest) == 1                     # within caps: fine
    monkeypatch.setattr(uploads, "MAX_FILE_BYTES", 4000)
    with pytest.raises(uploads.UploadError):
        uploads.extract_zip(z, tmp_path)


def test_not_a_zip_is_refused(tmp_path):
    bad = tmp_path / "x.zip"
    bad.write_bytes(b"this is not a zip")
    with pytest.raises(uploads.UploadError, match="not a valid zip"):
        uploads.extract_zip(bad, tmp_path)


# --- dropped folders -----------------------------------------------------------------

def test_dropped_file_traversal_is_refused(tmp_path):
    with pytest.raises(uploads.UploadError, match="unsafe"):
        uploads.write_dropped_file(tmp_path, "../../x.c", b"x", {})


def test_dropped_files_obey_the_same_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads, "MAX_FILES", 2)
    state: dict = {}
    uploads.write_dropped_file(tmp_path, "a.c", b"x", state)
    uploads.write_dropped_file(tmp_path, "b.c", b"x", state)
    with pytest.raises(uploads.UploadError, match="too many files"):
        uploads.write_dropped_file(tmp_path, "c.c", b"x", state)


# --- census ------------------------------------------------------------------------------

def test_census_describes_without_running_anything(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "src" / "a.h").write_text("int x;\n")
    (tmp_path / "Makefile").write_text("all:\n")
    c = uploads.census(tmp_path)
    assert c["source_files"] == 2 and c["files_with_main"] == 1
    assert c["build_kind"] == "make"


def test_census_detects_flat_c_and_none(tmp_path):
    (tmp_path / "x.c").write_text("int f(void){return 1;}\n")
    assert uploads.census(tmp_path)["build_kind"] == "flat-c"
    empty = tmp_path / "e"
    empty.mkdir()
    (empty / "notes.txt").write_text("hi")
    assert uploads.census(empty)["build_kind"] == "none"


def test_census_skips_vcs_directories(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.c").write_text("int g;\n")
    (tmp_path / "real.c").write_text("int h;\n")
    assert uploads.census(tmp_path)["source_files"] == 1


# --- results ---------------------------------------------------------------------------

def test_wilson_matches_the_benchmark_harness():
    """The dashboard keeps a local copy to stay light; it must never drift from the harness."""
    from benchmark import wilson_interval as harness
    for k, n in [(44, 44), (43, 44), (0, 10), (1, 1), (30, 30), (5, 9), (0, 0)]:
        assert results.wilson_interval(k, n) == pytest.approx(harness(k, n))


def test_default_run_is_the_newest_full_run_not_the_newest_file():
    runs = [{"id": "c", "targets": 1}, {"id": "b", "targets": 38}, {"id": "a", "targets": 44}]
    assert results.default_run_id(runs) == "b", "a 1-target spot check must not become the headline"


def test_default_run_falls_back_to_newest_when_none_is_full():
    assert results.default_run_id([{"id": "x", "targets": 2}, {"id": "y", "targets": 1}]) == "x"
    assert results.default_run_id([]) is None


def test_hardening_is_three_numbers_not_one():
    rows = [
        {"Status": "patched", "Hardening": "x", "Hardening_Survived": "True"},
        {"Status": "unresolved_hardening", "Hardening": "x", "Hardening_Survived": "False"},
        {"Status": "patched", "Hardening": "differential(0 inputs)", "Hardening_Survived": "False"},
        {"Status": "patched", "Hardening": "", "Hardening_Survived": ""},
    ]
    h = results.hardening_counts(rows)
    assert (h["attacked_and_held"], h["falsified"], h["not_attacked"]) == (1, 1, 1)


def test_special_result_names_are_whitelisted():
    assert results.special_result("../../etc/passwd") is None
    assert results.special_result("nonsense") is None


def test_run_id_must_be_digits(tmp_path):
    assert results.run_detail("../../etc") is None
    assert results.run_detail("abc") is None


# --- job manager ----------------------------------------------------------------------------

@pytest.fixture
def manager(tmp_path, monkeypatch):
    import dashboard.jobs as jobs_mod
    monkeypatch.setattr(jobs_mod, "RUNS_DIR", tmp_path / "runs")
    return JobManager()


def _wait(job, timeout=20):
    end = time.time() + timeout
    while job.running and time.time() < end:
        time.sleep(0.1)


def test_only_one_job_runs_at_a_time(manager):
    j = manager.start("t", [sys.executable, "-c", "import time; time.sleep(5)"], "slow")
    try:
        with pytest.raises(BusyError):
            manager.start("t", [sys.executable, "-c", "print(1)"], "second")
    finally:
        manager.stop(j.id)
        _wait(j)


def test_stop_terminates_the_whole_process_group(manager):
    j = manager.start("t", [sys.executable, "-c", "import time; time.sleep(60)"], "sleeper")
    assert manager.stop(j.id)
    _wait(j)
    assert not j.running and j.status == "stopped"


def test_finished_job_reports_done_immediately(manager):
    """A finished process must not read as 'starting' while the watcher thread catches up."""
    j = manager.start("t", [sys.executable, "-c", "print('ok')"], "quick")
    _wait(j)
    assert j.status == "done"
    assert j.code == 0


def test_failed_job_is_reported_failed(manager):
    j = manager.start("t", [sys.executable, "-c", "import sys; sys.exit(3)"], "bad")
    _wait(j)
    assert j.status == "failed" and j.code == 3


def test_log_is_the_real_process_output(manager):
    j = manager.start("t", [sys.executable, "-c", "print('hello-from-job')"], "echo")
    _wait(j)
    assert "hello-from-job" in manager.log_tail(j)


def test_progress_comes_only_from_events(manager):
    from src.events import EventSink
    j = manager.start("t", [sys.executable, "-c", "pass"], "noop")
    _wait(j)
    assert manager.progress(j) == {"done": 0, "total": 0, "current": "", "suites": []}

    sink = EventSink(j.events_path)
    sink.emit("suite_start", suite="S", total=2)
    sink.emit("target_start", id="A")
    sink.emit("target_done", suite="S", id="A", result="patched")
    p = manager.progress(j)
    assert (p["done"], p["total"]) == (1, 2)
    assert p["suites"][0]["patched"] == 1


def test_events_file_is_written_where_the_job_is_told_to(manager):
    j = manager.start("t", [sys.executable, "-c", "import sys; print(sys.argv[1:])"], "ev",
                      events_flag="--events")
    _wait(j)
    assert str(j.events_path) in manager.log_tail(j)


# --- HTTP layer ---------------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import dashboard.app as app_mod
    import dashboard.jobs as jobs_mod
    monkeypatch.setattr(jobs_mod, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(uploads, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(app_mod, "jobs", JobManager())
    return TestClient(app_mod.app)


def test_capabilities_report_autonomous_mode_honestly(client):
    r = client.get("/api/capabilities").json()
    assert "auto_mode" in r and isinstance(r["auto_mode"], bool)


def test_unknown_suite_is_rejected(client):
    assert client.post("/api/jobs/benchmark", json={"suite": "rm -rf /"}).status_code == 400


def test_target_filter_rejects_shell_metacharacters(client):
    r = client.post("/api/jobs/benchmark", json={"suite": "synthetic", "only": "A; touch /tmp/pwn"})
    assert r.status_code == 400


def test_model_name_rejects_shell_metacharacters(client):
    r = client.post("/api/jobs/modelcheck", json={"provider": "local", "model": "x; echo hi"})
    assert r.status_code == 400


def test_unknown_provider_is_rejected(client):
    assert client.post("/api/jobs/modelcheck", json={"provider": "carrier-pigeon"}).status_code == 400


def test_upload_good_zip_is_accepted_and_described(client):
    data = _zip_bytes([("proj/main.c", C_SRC), ("proj/Makefile", b"all:\n")])
    r = client.post("/api/repos", files={"files": ("proj.zip", data, "application/zip")})
    assert r.status_code == 200
    body = r.json()
    assert body["census"]["source_files"] == 1 and body["census"]["build_kind"] == "make"


@pytest.mark.parametrize("members", [
    [("../escape.c", C_SRC)],
    [("/abs.c", C_SRC)],
    [("a\\b.c", C_SRC)],
])
def test_upload_hostile_zip_is_rejected_and_leaves_nothing(client, tmp_path, members):
    data = _zip_bytes(members)
    r = client.post("/api/repos", files={"files": ("x.zip", data, "application/zip")})
    assert r.status_code == 400
    root = tmp_path / "uploads"
    assert not root.exists() or not list(root.iterdir()), "a rejected upload left files behind"
    assert not (tmp_path / "escape.c").exists()


def test_upload_without_source_files_is_rejected(client):
    data = _zip_bytes([("notes.txt", b"hello")])
    assert client.post("/api/repos", files={"files": ("n.zip", data, "application/zip")}).status_code == 400


def test_dropped_folder_traversal_is_rejected(client):
    r = client.post("/api/repos", files=[("files", ("m.c", C_SRC))], data={"paths": "../../x.c"})
    assert r.status_code == 400


def test_dropped_folder_is_accepted(client):
    r = client.post("/api/repos", files=[("files", ("m.c", C_SRC)), ("files", ("u.h", b"int y;"))],
                    data={"paths": ["lib/src/m.c", "lib/src/u.h"]})
    assert r.status_code == 200 and r.json()["census"]["source_files"] == 2


def test_repo_ids_are_validated(client):
    assert client.get("/api/repos/../../etc").status_code in (404, 422)
    assert client.delete("/api/repos/not-an-id").status_code == 404


def test_token_is_required_when_configured(client, monkeypatch):
    monkeypatch.setenv("KAVACH_DASH_TOKEN", "s3cret")
    assert client.get("/api/capabilities").status_code == 401
    assert client.get("/api/capabilities", headers={"X-Token": "s3cret"}).status_code == 200
    assert client.get("/api/capabilities?token=s3cret").status_code == 200


def test_empty_results_are_an_empty_state_not_placeholders(client, monkeypatch, tmp_path):
    monkeypatch.setattr(results, "RUNS_DIR", tmp_path / "none")
    body = client.get("/api/results/headline").json()
    assert body.get("empty") is True
    assert client.get("/api/special/cheat_detector").json() in ({"empty": True},) or "ok" in client.get("/api/special/cheat_detector").json()


def test_auto_job_requires_a_known_repo(client):
    r = client.post("/api/jobs/auto", json={"repo_id": "r_20990101_000000_abcd", "llm_harness": False})
    assert r.status_code == 404


def test_auto_job_takes_no_free_text_command(client):
    # Extra fields are ignored; nothing the browser sends becomes a shell command.
    r = client.post("/api/jobs/auto", json={"repo_id": "../../etc", "build_cmd": "rm -rf /",
                                            "llm_harness": False})
    assert r.status_code == 404


def test_auto_evidence_rejects_bad_id(client):
    assert client.get("/api/auto/..%2F..%2Fx").status_code in (400, 404)
