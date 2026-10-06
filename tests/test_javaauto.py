"""Java backend: splicer round-trip + parse errors + enclosing-method mapping."""
from src.javaauto import patch
from src.javaauto.static import _enclosing_function

SRC = """\
package x;
class CarService {
    @GetMapping("/level1")
    public String lookup(String id) {
        String q = "select * from cars where id=" + id;
        return db.run(q);
    }
    public int safe() { return 1; }
}
"""


def test_find_and_replace_method():
    span = patch.find_function_span(SRC, "lookup")
    assert span is not None
    orig = SRC.encode()[span[0]:span[1]].decode()
    assert "@GetMapping" in orig and "select * from cars" in orig   # annotation + body included
    fixed = ('public String lookup(String id) {\n'
             '    String q = "select * from cars where id=?";\n'
             '    return db.run(q, id);\n'
             '}')
    out = patch.replace_function(SRC, "lookup", fixed)
    assert out is not None
    assert "db.run(q, id)" in out and patch.parse_errors(out) == []
    assert "int safe()" in out                                     # the other method is untouched


def test_parse_errors_flags_broken_java():
    assert patch.parse_errors("class A { void f() { ") != []
    assert patch.parse_errors("class A { void f() {} }") == []


def test_enclosing_method():
    name, s, e = _enclosing_function(SRC.encode(), 5)              # the line with the SQL string
    assert name == "lookup" and s <= 5 <= e


def test_replace_missing_returns_none():
    assert patch.replace_function(SRC, "nope", "void nope(){}") is None
