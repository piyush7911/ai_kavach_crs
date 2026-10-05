"""Python patch mechanics for AI Kavach repair — the Python counterpart of src/jsauto/patch.py.

The model returns the full replacement for ONE function; it is spliced in by tree-sitter-python
byte range (not a textual diff), and the result is parse-checked before any gate runs. Whole-function
replacement is the lesson the C and JS backends already learned: a diff with slightly wrong context
is the main cause of apply failures, especially for small local models.
"""
from __future__ import annotations

import textwrap

import tree_sitter_python
from tree_sitter import Language, Parser

_PY = Language(tree_sitter_python.language())


def _parser() -> Parser:
    return Parser(_PY)


def parse_errors(source: str) -> list[str]:
    """Human-readable syntax errors ('line N: ...'), empty if the source parses cleanly."""
    tree = _parser().parse(source.encode())
    out = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            what = "missing node" if n.is_missing else "syntax error"
            out.append(f"line {n.start_point[0] + 1}: {what}")
        stack.extend(n.children)
    return out


def find_function_span(source: str, name: str) -> tuple[int, int] | None:
    """(start_byte, end_byte) of the `def name(...)` statement, or None. Includes decorators."""
    src = source.encode()
    tree = _parser().parse(src)
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            name_node = n.child_by_field_name("name")
            if name_node and src[name_node.start_byte:name_node.end_byte].decode() == name:
                node = n
                # include immediately-preceding decorators
                if n.parent and n.parent.type == "decorated_definition":
                    node = n.parent
                return node.start_byte, node.end_byte
        stack.extend(n.children)
    return None


def replace_function(source: str, name: str, new_function: str) -> str | None:
    """Splice `new_function` in place of `def name`. Returns the new source, or None if the
    function is not found. Indentation of the replacement is matched to the original's column."""
    span = find_function_span(source, name)
    if span is None:
        return None
    start, end = span
    src = source.encode()
    # Align the replacement to the original function's indentation.
    col = 0
    i = start
    while i > 0 and src[i - 1:i] in (b" ", b"\t"):
        col += 1
        i -= 1
    body = _reindent(new_function, col)
    return src[:start].decode() + body + src[end:].decode()


def _reindent(text: str, col: int) -> str:
    """Match a model-returned function to the original's indentation. `src[:start]` already supplies
    the first line's indent, so the `def` line sits at column 0 here; every later line gets `col`
    more spaces on top of its own relative indent. The model's own common indent is removed first."""
    dedented = textwrap.dedent(text.strip("\n")).split("\n")
    pad = " " * col
    out = [dedented[0]]
    for ln in dedented[1:]:
        out.append(pad + ln if ln.strip() else "")
    return "\n".join(out)
