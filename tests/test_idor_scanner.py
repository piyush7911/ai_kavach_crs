import json
from benchmarks.scanners.idor import findings_from_idor


def test_detects_object_refs_skips_safe(tmp_path):
    rm = {"routes": [
        {"method": "GET", "path": "/users/{userId}/profile", "file": "U.java", "function": "profile", "params": []},
        {"method": "POST", "path": "/transfer", "file": "T.java", "function": "xfer", "params": ["accountId"]},
        {"method": "GET", "path": "/public/health", "file": "H.java", "function": "health", "params": []},
        {"method": "POST", "path": "/login", "file": "L.java", "function": "login", "params": ["username"]}]}
    p = tmp_path / "routes.json"
    p.write_text(json.dumps(rm))
    fs = findings_from_idor(str(p))
    routes = {f.evidence["route"] for f in fs}
    assert "GET /users/{userId}/profile" in routes          # path id segment
    assert "POST /transfer" in routes                        # accountId ownership ref
    assert "GET /public/health" not in routes                # no object ref
    assert "POST /login" not in routes                       # login route skipped (not cross-user read)
    assert all(f.klass == "idor" and f.status == "candidate" for f in fs)


def test_function_scoped_ownership_check_suppresses(tmp_path):
    (tmp_path / "A.java").write_text(
        "class A {\n  Obj get(@RequestParam Long ownerId){\n    if(!ownerId.equals(getCurrentUser())) deny();\n    return load(ownerId);\n  }\n}")
    rm = {"routes": [{"method": "GET", "path": "/a", "file": "A.java", "function": "get", "params": ["ownerId"]}]}
    p = tmp_path / "routes.json"
    p.write_text(json.dumps(rm))
    assert findings_from_idor(str(p), str(tmp_path)) == []   # ownership check in the handler -> suppressed
