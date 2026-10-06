from benchmarks.scanners.joern import findings_from_joern


def test_parses_flow_rows_skips_meta(tmp_path):
    tsv = tmp_path / "t.tsv"
    tsv.write_text(
        "META\tsources\t294\n"
        "META\tsinks:sql-injection\t50\n"
        "FLOW\tsql-injection\tsrc/Foo.java\t143\thandler\tsrc/Dao.java\t20\tquery\n"
        "FLOW\tdeserialization\tsrc/Bar.java\t-1\tparse\tsrc/Bar.java\t9\treadObject\n"
        "bad\trow\n")
    fs = findings_from_joern(str(tsv))
    assert len(fs) == 2
    f0 = fs[0]
    assert f0.klass == "sql-injection" and f0.file == "src/Foo.java" and f0.function == "handler"
    assert f0.line == 143 and f0.status == "candidate" and f0.source == "joern"
    assert f0.evidence["sink"]["function"] == "query"
    assert fs[1].klass == "insecure-deserialization" and fs[1].line == 0   # -1 clamped


def test_missing_file_returns_empty():
    assert findings_from_joern("/no/such.tsv") == []
