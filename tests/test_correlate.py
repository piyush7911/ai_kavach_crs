"""correlate(): join a code-location candidate to the route its handler serves."""
from src.pyauto.probes import Route
from src.jsauto.findings import Finding
from src.pyauto.correlate import correlate


def _cand(file, func="", klass="sql-injection"):
    return Finding(id="c", source="opengrep", status="candidate", klass=klass, file=file, function=func)


def test_correlate_by_file_stem_to_path_segment():
    routes = [Route("GET", "/VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1"),
              Route("GET", "/other/LEVEL_1")]
    c = _cand("sqlInjection/ErrorBasedSQLInjectionVulnerability.java")
    bound = correlate([c], routes)
    assert len(bound) == 1
    assert c.evidence["route"] == "GET /VulnerableApp/ErrorBasedSQLInjectionVulnerability/LEVEL_1"


def test_correlate_by_operation_id():
    r = Route("GET", "/users/v1/{username}", operation_id="api_views.users.get_by_username")
    c = _cand("api_views/users.py", "get_by_username")
    bound = correlate([c], [r])
    assert bound and c.evidence["route"] == "GET /users/v1/{username}"


def test_no_match_leaves_untouched():
    c = _cand("totally/Unrelated.java")
    assert correlate([c], [Route("GET", "/foo/LEVEL_1")]) == []
    assert "route" not in (c.evidence or {})
