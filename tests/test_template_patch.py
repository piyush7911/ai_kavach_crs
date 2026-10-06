from src.autonomy.template_patch import apply_templates, template_repair, has_template


def test_weak_hash_java_swap():
    out, ok, note = apply_templates("weak-hash", "X.java", 'getInstance("MD5")')
    assert ok and out == 'getInstance("SHA-256")' and "SHA-256" in note


def test_dependency_refused():
    out, ok, note = apply_templates("vulnerable-dependency", "pom.xml", "<version>1.0</version>")
    assert not ok and out == "<version>1.0</version>" and "advisory-only" in note
    assert not has_template("vulnerable-dependency", "pom.xml")


def test_template_repair_produces_verified_diff(tmp_path):
    f = tmp_path / "A.java"
    f.write_text("class A { void m(){ c.setSecure(false); } }")
    r = template_repair({"klass": "cookie-flags", "file": "A.java"}, str(tmp_path))
    assert r and r["status"] == "proven" and "setSecure(true)" in r["diff"]
    assert f.read_text() == "class A { void m(){ c.setSecure(false); } }"   # target NOT modified


def test_template_repair_none_without_template(tmp_path):
    (tmp_path / "A.java").write_text("x")
    assert template_repair({"klass": "business-logic", "file": "A.java"}, str(tmp_path)) is None
