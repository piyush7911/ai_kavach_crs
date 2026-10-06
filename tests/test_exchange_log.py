from src.autonomy.exchange_log import ExchangeLog, verify, load_ids
from pathlib import Path


def test_log_and_verify_rejects_fabricated(tmp_path):
    log = str(tmp_path / "exchanges.jsonl")
    xl = ExchangeLog(log)
    a = xl.record("GET", "/x?id=1 OR 1=1", 200, resp_preview="2 rows")
    b = xl.record("GET", "/x?id=1 AND 1=2", 200)
    assert (a, b) == ("1", "2")
    known, rejected = verify([a, b, "999"], log)
    assert known == ["1", "2"] and rejected == ["999"]
    assert load_ids(log) == {"1", "2"}
