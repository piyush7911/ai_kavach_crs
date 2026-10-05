"""Offline self-checks for the scoring/matching logic (no server needed).

Run: python -m benchmarks.nodegoat.test_score   (or pytest)
Covers the bits that bit us: file+line matching, the CWE tiebreak for two vulns
close together in one file, dependency de-duplication, and informational exclusion.
"""
from benchmarks.nodegoat.runner import _best_match, _same_site, _score

VULNS = [
    {"id": "V-XSS", "file": "app/routes/profile.js", "line": 64, "class": "xss", "cwe": "CWE-79"},
    {"id": "V-REDOS", "file": "app/routes/profile.js", "line": 59, "class": "redos", "cwe": "CWE-1333"},
    {"id": "V-DEP", "file": "package.json", "line": 0, "class": "vulnerable-dependency", "cwe": "CWE-1035"},
]


def test_line_window():
    assert _same_site({"file": "a/profile.js", "line": 60}, VULNS[0])      # 60 vs 64 within 5
    assert not _same_site({"file": "a/profile.js", "line": 40}, VULNS[0])  # too far
    assert not _same_site({"file": "a/other.js", "line": 64}, VULNS[0])    # wrong file


def test_cwe_tiebreak_resolves_collision():
    # A redos finding sits 5 lines from the xss vuln; CWE must send it to V-REDOS.
    redos = {"file": "app/routes/profile.js", "line": 59, "klass": "redos", "cwe": "CWE-1333"}
    assert _best_match(redos, VULNS)["id"] == "V-REDOS"


def test_line_zero_is_file_level():
    assert _same_site({"file": "package.json", "line": 123}, VULNS[2])  # dep line 0 = whole file


def test_score_dedupes_dependencies_and_excludes_informational():
    findings = (
        [{"file": "package.json", "line": 0, "klass": "vulnerable-dependency", "cwe": "CWE-1035"}] * 10
        + [{"file": "app/routes/profile.js", "line": 59, "klass": "redos", "cwe": "CWE-1333"}]
        + [{"file": "seeds/db.js", "line": 1, "klass": "hardcoded-secret", "status": "informational"}]
    )
    r = _score(findings, VULNS)
    assert r["informational_excluded"] == 1
    assert r["found"] == ["V-DEP", "V-REDOS"]      # dep + redos matched, xss missed
    assert r["recall"] == round(2 / 3, 3)
    # 10 dep findings collapse to one group → precision counts them once, not 10x
    assert r["precision"] == 1.0                    # both scored groups hit a real vuln


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")


if __name__ == "__main__":
    _run()
