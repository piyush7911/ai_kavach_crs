from benchmarks.scanners.joern import findings_from_joern


def test_parses_flow_rows_skips_meta(tmp_path):
    tsv = tmp_path / "t.tsv"
    # FLOW row is SINK first, SOURCE second (per joern_taint.sc): sink=Dao/query, source=Controller/handler
    tsv.write_text(
        "META\tsources\t294\n"
        "META\tsinks:sql-injection\t50\n"
        "FLOW\tsql-injection\tsrc/Dao.java\t20\tquery\tsrc/Controller.java\t143\thandler\n"
        "FLOW\tdeserialization\tsrc/Bar.java\t9\treadObject\tsrc/Bar.java\t-1\tparse\n"
        "bad\trow\n")
    fs = findings_from_joern(str(tsv))
    assert len(fs) == 2
    f0 = fs[0]
    # anchored to the SOURCE handler (for correlate->route), sink in evidence (for the fix)
    assert f0.klass == "sql-injection" and f0.file == "src/Controller.java" and f0.function == "handler"
    assert f0.line == 143 and f0.status == "candidate" and f0.source == "joern"
    assert f0.evidence["sink"]["function"] == "query" and f0.evidence["sink"]["file"] == "src/Dao.java"
    assert fs[1].klass == "insecure-deserialization" and fs[1].line == 0   # source line -1 clamped


def test_missing_file_returns_empty():
    assert findings_from_joern("/no/such.tsv") == []
