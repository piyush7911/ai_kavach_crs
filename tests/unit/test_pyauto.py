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
