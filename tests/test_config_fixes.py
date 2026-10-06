from src.autonomy.config_fixes import detect_framework, remediation_for


def test_detect_express(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"4"}}')
    assert detect_framework(tmp_path) == "express"


def test_detect_flask(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.0\n")
    assert detect_framework(tmp_path) == "flask"


def test_remediation_framework_aware(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"4"}}')
    r = remediation_for("clickjacking", tmp_path)
    assert r and r["framework"] == "express" and "frameguard" in r["snippet"] and r["verify"]
    assert remediation_for("no-rate-limit", tmp_path)["snippet"].startswith("app.use")


def test_no_remediation_for_unknown_class(tmp_path):
    assert remediation_for("sql-injection", tmp_path) is None     # injection has a code fix, not a config one
