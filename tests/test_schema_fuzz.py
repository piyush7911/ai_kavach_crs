from src.pyauto.schema_fuzz import _value, _requests_for, schema_fuzz


def test_value_types():
    assert _value({"type": "integer"}) == 1 and _value({"type": "integer"}, "big") == 999999999
    assert _value({"type": "boolean"}) is True and _value({"type": "string"}, "empty") == ""


def test_requests_for_fills_path_and_query():
    filled, variants = _requests_for("/users/{id}", "get",
                                     {"parameters": [{"in": "path", "name": "id", "schema": {"type": "integer"}},
                                                     {"in": "query", "name": "q", "schema": {"type": "string"}}]})
    assert filled == "/users/1" and variants[0][0] == {"q": "kvtest"}
    assert len(variants) == 2                            # base + one edge variant


def test_no_spec_no_findings():
    assert schema_fuzz("http://127.0.0.1:9", spec=None) == []
