import json
from src.pyauto.param_source import build_param_lookup
from src.pyauto.correlate import correlate_with_routemap
from src.jsauto.findings import Finding


def test_param_extract_java_const_and_python(tmp_path):
    (tmp_path / "Constants.java").write_text('interface C { String ID = "id"; }')
    (tmp_path / "Ctrl.java").write_text(
        'class Ctrl { String f(@RequestParam Map q){ return q.get(Constants.ID); }\n'
        '  String g(@RequestParam("name") String n){ return n; } }')
    (tmp_path / "views.py").write_text("def h(): return request.args.get('q')\n")
    lk = build_param_lookup(str(tmp_path))
    assert set(lk("Ctrl.java")) == {"id", "name"}         # const-resolved + literal annotation
    assert lk("views.py") == ["q"]


def test_routemap_bridge_maps_and_expands(tmp_path):
    rm = {"routes": [
        {"file": "org/x/Ctrl.java", "function": "f", "method": "ANY", "path": "Ctrl/LEVEL_1"},
        {"file": "org/x/Other.java", "function": "f", "method": "GET", "path": "Other/LEVEL_1"}]}
    p = tmp_path / "routes.json"
    p.write_text(json.dumps(rm))
    cands = [Finding(id="j1", source="joern", klass="sql-injection", file="src/org/x/Ctrl.java",
                     function="f", status="candidate", evidence={})]
    bound = correlate_with_routemap(cands, str(p), lambda base: ["id", "name"])
    routes = {b.evidence["route"] for b in bound}
    assert routes == {"GET /Ctrl/LEVEL_1"}                # ANY->GET, leading slash, matched by (base,func)
    assert {b.evidence["param"] for b in bound} == {"id", "name"}   # one copy per wire param


def test_routemap_skips_unmapped(tmp_path):
    p = tmp_path / "routes.json"
    p.write_text(json.dumps({"routes": []}))
    cands = [Finding(id="j1", source="joern", klass="xss", file="A.java", function="z", status="candidate", evidence={})]
    assert correlate_with_routemap(cands, str(p), lambda b: ["x"]) == []
