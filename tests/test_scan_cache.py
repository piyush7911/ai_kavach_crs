from src.autonomy import scan_cache
from src.jsauto.findings import Finding


def test_fingerprint_stable_then_changes(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    fp1 = scan_cache.tree_fingerprint(tmp_path)
    assert fp1 == scan_cache.tree_fingerprint(tmp_path)        # stable on unchanged tree
    import time; time.sleep(0.01)
    (tmp_path / "a.py").write_text("x=2")
    assert scan_cache.tree_fingerprint(tmp_path) != fp1        # changes when a file changes


def test_cache_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_cache, "_CACHE_DIR", tmp_path / "c")
    (tmp_path / "a.py").write_text("x=1")
    assert scan_cache.load(tmp_path, "opengrep", "r") is None   # miss
    f = Finding(id="1", source="opengrep", klass="sql-injection", file="a.py", status="candidate")
    scan_cache.save(tmp_path, "opengrep", [f], "r")
    got = scan_cache.load(tmp_path, "opengrep", "r")            # hit
    assert got and got[0].klass == "sql-injection" and got[0].file == "a.py"
    # a changed tree => cache miss (no stale result)
    import time; time.sleep(0.01); (tmp_path / "a.py").write_text("x=2")
    assert scan_cache.load(tmp_path, "opengrep", "r") is None
