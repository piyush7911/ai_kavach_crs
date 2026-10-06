from src.jsauto.findings import Finding
from src.autonomy.finding_gate import gate_finding, fill_from_oracle, validate_report


def test_confirmed_injection_passes():
    f = Finding(id="1", source="probe", klass="sql-injection", file="(runtime)", status="confirmed",
                exploit={"differential": {"true_request": {"method": "GET", "path": "/x?id=1 OR 1=1"}}},
                reason="injection true≠false")
    ok, errs = gate_finding(f)
    assert ok, errs
    assert f.confidence == "high" and "control" in f.counterevidence and f.severity_change_conditions


def test_confirmed_fact_passes_without_exploit():
    f = Finding(id="2", source="misuse", klass="weak-hash", file="A.java", status="confirmed",
                reason="direct weak-hash literal at A.java:10", evidence={"line_text": 'getInstance("MD5")'})
    ok, errs = gate_finding(f)
    assert ok, errs                                       # a deterministic fact is its own poc


def test_bare_confirmed_fails():
    d = {"klass": "xss", "status": "confirmed"}            # no exploit, no evidence
    fill_from_oracle(d)
    assert validate_report(d)                              # cannot be claimed


def test_patch_without_verification_fails():
    d = {"klass": "weak-hash", "status": "confirmed", "evidence_text": "MD5 literal", "patch": "--- a\n+++ b\n"}
    fill_from_oracle(d)
    assert any("fix_verification" in e for e in validate_report(d))
