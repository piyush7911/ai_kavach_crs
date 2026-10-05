"""Offline checks for the Python detector's function mapping (no semgrep needed)."""
from src.pyauto.static import _enclosing_function

SRC = b'''import os

def outer(x):
    y = eval(x)          # line 4
    return y

class C:
    def method(self, a):
        return a + 1     # line 9
'''


def test_maps_line_to_enclosing_function():
    assert _enclosing_function(SRC, 4)[0] == "outer"
    assert _enclosing_function(SRC, 9)[0] == "method"


def test_line_outside_any_function():
    assert _enclosing_function(SRC, 1)[0] == ""   # the import line


def test_splicer_replaces_a_function_and_keeps_valid_python():
    from src.pyauto.patch import replace_function, parse_errors, find_function_span
    import ast
    src = "import os\n\n\ndef target(x):\n    return eval(x)\n\n\ndef other():\n    return 1\n"
    new = replace_function(src, "target", "def target(x):\n    return int(x)\n")
    assert new is not None
    assert parse_errors(new) == []
    ast.parse(new)                       # valid Python
    assert "int(x)" in new and "eval(x)" not in new
    assert "def other():" in new         # other function untouched
    assert find_function_span(src, "missing") is None


def test_splicer_matches_indentation_of_a_method():
    from src.pyauto.patch import replace_function
    import ast
    src = "class C:\n    def m(self):\n        return bad()\n"
    new = replace_function(src, "m", "def m(self):\n    return good()\n")
    ast.parse(new)                       # indentation preserved → still parses inside the class
    assert "return good()" in new
