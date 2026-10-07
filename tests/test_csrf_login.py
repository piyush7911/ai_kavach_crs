from benchmarks.oracle_engine import Session


def test_csrf_token_scraped_both_orders(monkeypatch):
    s = Session("http://127.0.0.1:1", auth={"login_path": "/login", "csrf_field": "user_token"})
    # name-before-value
    monkeypatch.setattr(s, "request", lambda m, p, **k: type("R", (), {"body": "<input name='user_token' value='AAA'>"})())
    assert s._csrf_token(s.auth) == {"user_token": "AAA"}
    # value-before-name
    monkeypatch.setattr(s, "request", lambda m, p, **k: type("R", (), {"body": '<input value="BBB" name="user_token">'})())
    assert s._csrf_token(s.auth) == {"user_token": "BBB"}
    # no csrf_field -> no token
    assert Session("http://127.0.0.1:1", auth={"login_path": "/x"})._csrf_token({"login_path": "/x"}) == {}


def test_static_cookies_set_in_jar():
    s = Session("http://127.0.0.1:8081", auth={"cookies": {"security": "low"}})
    s._set_static_cookies()
    assert any(c.name == "security" and c.value == "low" for c in s.jar)
