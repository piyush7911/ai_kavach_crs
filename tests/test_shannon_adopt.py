from src.autonomy.severity import refine
from src.autonomy.candidate_sanity import sanity
from src.jsauto.findings import Finding
from src.autonomy.finding_gate import gate_finding


def test_severity_lowered_by_auth_and_refutation():
    r = refine({"severity": "high", "klass": "sql-injection", "status": "confirmed",
                "reachability": "AUTHENTICATED", "reason": "x"})
    assert r["severity"] == "medium"
    r2 = refine({"severity": "high", "klass": "idor", "status": "confirmed",
                 "reason": "attacker can't read the blob"})
    assert r2["severity"] == "medium" and r2["warnings"]


def test_gate_applies_honest_severity():
    f = Finding(id="1", source="probe", klass="clickjacking", file="(runtime)", status="confirmed",
                severity="medium", reason="no X-Frame-Options", evidence={"detail": "absent"})
    gate_finding(f)
    assert f.severity == "low"                            # no-consequence floor applied via the gate


def test_sanity_drops_hallucinated(tmp_path):
    (tmp_path / "R.java").write_text("class R { void h(){} }")
    assert sanity({"status": "candidate", "klass": "xss", "file": "Ghost.java"}, str(tmp_path))[0] == "drop"
    assert sanity({"status": "candidate", "klass": "sql-injection", "file": "R.java", "function": "h",
                   "evidence": {"param": "x"}}, str(tmp_path))[0] == "ok"
