from src.autonomy import rescan_gate
from src.jsauto.findings import Finding


def test_sibling_sinks_excludes_patched_file(monkeypatch):
    import benchmarks.scanners.opengrep as og
    monkeypatch.setattr(og, "_binary", lambda: "opengrep")
    monkeypatch.setattr(og, "findings_from_opengrep", lambda p: [
        Finding(id="1", source="opengrep", klass="sql-injection", file="a.py", line=5, status="candidate"),
        Finding(id="2", source="opengrep", klass="sql-injection", file="b.py", line=9, status="candidate")])
    sibs = rescan_gate.sibling_sinks("tree", "sql-injection", exclude_files={"a.py"})
    assert len(sibs) == 1 and sibs[0].file == "b.py"     # the patched file excluded, the twin surfaces


def test_sibling_sinks_empty_without_scanner(monkeypatch):
    import benchmarks.scanners.opengrep as og
    monkeypatch.setattr(og, "_binary", lambda: None)
    assert rescan_gate.sibling_sinks("tree", "xss", set()) == []
