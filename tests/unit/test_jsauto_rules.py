"""
The vendored Node/Express Semgrep rules, checked against an annotated fixture.

`// ruleid: X` lines must be flagged by rule X and `// ok: X` lines must not be, so a rule that
starts over-matching (precision loss) fails here just as one that stops matching does.
Offline: the rules are files in config/semgrep, nothing is fetched.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "config" / "semgrep" / "kavach_js.yaml"
FIXTURE = ROOT / "tests" / "jsauto" / "rules_fixture.js"
pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None and not (Path(sys.executable).parent / "semgrep").exists(),
                                reason="semgrep not installed")


def _semgrep() -> str:
    local = Path(sys.executable).parent / "semgrep"
    return str(local) if local.exists() else shutil.which("semgrep")


def _annotations():
    lines = FIXTURE.read_text().splitlines()
    expected, forbidden = set(), set()
    for i, line in enumerate(lines):
        m = re.match(r"\s*//\s*(ruleid|ok):\s*(\S+)", line)
        if m:
            (expected if m.group(1) == "ruleid" else forbidden).add((m.group(2), i + 2))   # next line (1-based)
    return expected, forbidden


def _found():
    out = subprocess.run([_semgrep(), "--metrics=off", "--disable-version-check", "--quiet", "--json",
                          "--config", str(RULES), str(FIXTURE)], capture_output=True, text=True, timeout=120)
    data = json.loads(out.stdout)
    assert not data["errors"], data["errors"][:2]
    return {(r["check_id"].split(".")[-1], r["start"]["line"]) for r in data["results"]}


def test_every_annotated_positive_is_found_and_no_negative_is_flagged():
    expected, forbidden = _annotations()
    found = _found()
    missed = sorted(expected - found)
    false_pos = sorted(forbidden & found)
    assert not missed, f"rules missed: {missed}"
    assert not false_pos, f"rules over-matched: {false_pos}"


def test_nothing_unannotated_is_flagged():
    """Any hit on an unmarked line is an unreviewed false positive."""
    expected, forbidden = _annotations()
    extra = sorted(_found() - expected)
    assert not extra, f"unannotated findings: {extra}"
