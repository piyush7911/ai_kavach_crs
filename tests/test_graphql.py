from src.pyauto import probes  # noqa: F401 (ensure import graph OK)
from benchmarks.scanners.graphql import _query_fields, findings_from_graphql
import json


def test_query_fields_parses_introspection():
    schema = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}, "types": [
        {"name": "Query", "fields": [
            {"name": "user", "args": [{"name": "id"}]},
            {"name": "search", "args": [{"name": "q"}]}]}]}}})
    fields = _query_fields(schema)
    assert {"field": "user", "args": ["id"]} in fields


def test_no_graphql_endpoint_no_findings():
    # nothing listening -> find_graphql returns None -> [] (no FP)
    assert findings_from_graphql("http://127.0.0.1:9") == []
