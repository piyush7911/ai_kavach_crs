"""
Offline dependency audit: semver matching, lockfile graph attribution, and the guarantee that the default
path never touches the network (the rules of engagement do not allow the npm registry).
"""

import json
import subprocess
from pathlib import Path

import pytest

from src.jsauto import advisories as adv
from src.jsauto import deps


# -- semver and ranges ----------------------------------------------------------------------------------

def test_semver_ordering_follows_the_spec():
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0", "1.0.1", "1.10.0", "2.0.0"]
    keys = [adv.parse_version(v) for v in order]
    assert keys == sorted(keys) and len(set(keys)) == len(keys)
    assert adv.parse_version("v1.2") == adv.parse_version("1.2.0")
    assert adv.parse_version("not-a-version") is None


@pytest.mark.parametrize("version,expected", [
    ("0.0.1", True), ("4.6.4", True), ("4.6.5", False), ("5.0.0", False),
])
def test_introduced_zero_and_fixed(version, expected):
    assert adv.affected(version, [[{"introduced": "0"}, {"fixed": "4.6.5"}]]) is expected


def test_multiple_ranges_last_affected_and_open_ended():
    ranges = [[{"introduced": "1.0.0"}, {"fixed": "1.2.0"}], [{"introduced": "2.0.0"}, {"last_affected": "2.3.0"}],
              [{"introduced": "4.0.0"}]]
    got = {v: adv.affected(v, ranges) for v in ["0.9.0", "1.1.0", "1.2.0", "2.3.0", "2.3.1", "3.9.9", "4.0.0", "9.0.0"]}
    assert got == {"0.9.0": False, "1.1.0": True, "1.2.0": False, "2.3.0": True, "2.3.1": False,
                   "3.9.9": False, "4.0.0": True, "9.0.0": True}


def test_explicit_version_list_and_unparseable_versions():
    assert adv.affected("1.2.3", [], versions=["1.2.3"])
    assert not adv.affected("garbage", [[{"introduced": "0"}]])


def test_first_fix_is_the_lowest_fix_above_the_installed_version():
    ranges = [[{"introduced": "0"}, {"fixed": "1.5.0"}], [{"introduced": "2.0.0"}, {"fixed": "2.4.0"}]]
    assert adv.first_fix("1.0.0", ranges) == "1.5.0"
    assert adv.first_fix("2.1.0", ranges) == "2.4.0"
    assert adv.first_fix("3.0.0", ranges) == ""


# -- lockfile graph ---------------------------------------------------------------------------------------

SNAP = {"meta": {"built": "test", "advisories": 3}, "packages": {
    "leaf": [{"id": "GHSA-leaf", "aliases": [], "summary": "leaf is bad", "severity": "high", "cwe": "CWE-1",
              "ranges": [[{"introduced": "0"}, {"fixed": "2.0.0"}]], "versions": []}],
    "direct": [{"id": "GHSA-direct", "aliases": [], "summary": "direct is bad", "severity": "critical",
                "cwe": "CWE-2", "ranges": [[{"introduced": "0"}, {"fixed": "3.0.0"}]], "versions": []}],
    "devtool": [{"id": "GHSA-dev", "aliases": [], "summary": "dev only", "severity": "critical", "cwe": "",
                 "ranges": [[{"introduced": "0"}]], "versions": []}]}}


def project(tmp_path, packages, declared):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": declared}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 2, "packages": packages}))
    return tmp_path


def test_a_vulnerable_transitive_dependency_is_attributed_to_the_direct_package_that_pulls_it_in(tmp_path):
    root = project(tmp_path, {
        "": {"dependencies": {"web": "^1"}},
        "node_modules/web": {"version": "1.0.0", "dependencies": {"mid": "^1"}},
        "node_modules/mid": {"version": "1.0.0", "dependencies": {"leaf": "^1"}},
        "node_modules/leaf": {"version": "1.5.0"}}, {"web": "^1"})
    out = deps.audit(root, snapshot=SNAP)
    (f,) = out["findings"]
    assert f.evidence["package"] == "web" and f.evidence["via_packages"] == ["leaf"] and f.severity == "high"
    assert f.evidence["fix_version"] == ""                       # the fix is in `leaf`, via an update of `web`


def test_the_direct_package_itself_gets_a_published_fix_version(tmp_path):
    root = project(tmp_path, {"": {"dependencies": {"direct": "^1"}},
                              "node_modules/direct": {"version": "1.0.0"}}, {"direct": "^1"})
    (f,) = deps.audit(root, snapshot=SNAP)["findings"]
    assert f.evidence["fix_version"] == "3.0.0" and f.evidence["fix_is_major_bump"] is True


def test_fixed_versions_and_dev_only_packages_are_not_reported(tmp_path):
    root = project(tmp_path, {
        "": {"dependencies": {"direct": "^3", "web": "^1"}},
        "node_modules/direct": {"version": "3.0.0"},                       # at the fixed version
        "node_modules/web": {"version": "1.0.0", "dependencies": {"devtool": "*"}},
        "node_modules/devtool": {"version": "1.0.0", "dev": True}}, {"direct": "^3", "web": "^1"})
    assert deps.audit(root, snapshot=SNAP)["findings"] == []


def test_nested_node_modules_resolve_to_the_nearest_copy(tmp_path):
    root = project(tmp_path, {
        "": {"dependencies": {"web": "^1"}},
        "node_modules/web": {"version": "1.0.0", "dependencies": {"leaf": "^2"}},
        "node_modules/web/node_modules/leaf": {"version": "2.0.0"},       # the copy web actually loads (safe)
        "node_modules/leaf": {"version": "1.0.0"}}, {"web": "^1"})       # a hoisted vulnerable copy it does not
    assert deps.audit(root, snapshot=SNAP)["findings"] == []


# -- honesty and the network ------------------------------------------------------------------------------

def test_the_default_audit_never_touches_the_network(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the offline audit tried to run a subprocess (npm)")
    monkeypatch.setattr(subprocess, "run", boom)
    root = project(tmp_path, {"": {"dependencies": {"direct": "^1"}},
                              "node_modules/direct": {"version": "1.0.0"}}, {"direct": "^1"})
    out = deps.audit(root, snapshot=SNAP)
    assert out["mode"] == "offline" and len(out["findings"]) == 1


def test_missing_lockfile_or_snapshot_is_an_error_not_a_clean_result(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    assert "NOT a clean result" in deps.audit(tmp_path, snapshot=SNAP)["error"]
    v1 = tmp_path / "v1"
    v1.mkdir()
    (v1 / "package.json").write_text("{}")
    (v1 / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    assert "lockfile v1" in deps.audit(v1, snapshot=SNAP)["error"]


def test_the_shipped_snapshot_loads_and_is_labelled():
    snap = adv.load()
    assert snap["meta"]["advisories"] > 1000 and snap["meta"]["built"] and "malware" in snap["meta"]["source"]
    assert "express" in snap["packages"] and all("ranges" in a for a in snap["packages"]["express"])
