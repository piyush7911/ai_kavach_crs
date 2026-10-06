from src.autonomy import rescan_gate
from src.jsauto.findings import Finding


def test_skipped_when_no_scanner(monkeypatch):
    import benchmarks.scanners.opengrep as og
    monkeypatch.setattr(og, "_binary", lambda: None)
    cleared, detail = rescan_gate.flow_cleared("x.py", "sql-injection")
    assert cleared and "skipped" in detail            # never block when scanner absent


def test_rejects_when_class_flow_remains(monkeypatch):
    import benchmarks.scanners.opengrep as og
    monkeypatch.setattr(og, "_binary", lambda: "opengrep")
    monkeypatch.setattr(og, "findings_from_opengrep",
                        lambda p: [Finding(id="1", source="opengrep", klass="sql-injection", file="x.py", line=9, status="candidate")])
    cleared, detail = rescan_gate.flow_cleared("x.py", "sql-injection")
    assert not cleared and "STILL present" in detail


def test_clean_when_class_gone(monkeypatch):
    import benchmarks.scanners.opengrep as og
    monkeypatch.setattr(og, "_binary", lambda: "opengrep")
    monkeypatch.setattr(og, "findings_from_opengrep",
                        lambda p: [Finding(id="1", source="opengrep", klass="xss", file="x.py", status="candidate")])
    cleared, detail = rescan_gate.flow_cleared("x.py", "sql-injection")   # a different class remains, ours is gone
    assert cleared and "clean" in detail
