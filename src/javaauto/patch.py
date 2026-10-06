"""Java patch mechanics — the Java counterpart of src/pyauto/patch.py and src/jsauto/patch.py.

The model returns the full replacement for ONE method; it is spliced in by tree-sitter-java byte range
(not a textual diff) and parse-checked before any gate runs. Whole-method replacement is the lesson the
other backends already learned: a diff with slightly wrong context is the main cause of apply failures,
especially for small local models. The method's leading annotations/modifiers are part of the span, so a
route annotation like `@...RequestMapping` is preserved only if the model keeps it — the prompt says to.
"""
from __future__ import annotations

import textwrap

import tree_sitter_java
from tree_sitter import Language, Parser

_JAVA = Language(tree_sitter_java.language())
_METHOD_NODES = ("method_declaration", "constructor_declaration")


def _parser() -> Parser:
    return Parser(_JAVA)


def parse_errors(source: str) -> list[str]:
    """Human-readable syntax errors ('line N: ...'), empty if the source parses cleanly."""
    tree = _parser().parse(source.encode())
    out = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            out.append(f"line {n.start_point[0] + 1}: {'missing node' if n.is_missing else 'syntax error'}")
        stack.extend(n.children)
    return out


def find_function_span(source: str, name: str) -> tuple[int, int] | None:
    """(start_byte, end_byte) of the `... name(...) {...}` method/constructor, or None. The span includes
    the method's leading modifiers and annotations (tree-sitter-java nests them in the declaration)."""
    src = source.encode()
    tree = _parser().parse(src)
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in _METHOD_NODES:
            name_node = n.child_by_field_name("name")
            if name_node and src[name_node.start_byte:name_node.end_byte].decode() == name:
                return n.start_byte, n.end_byte
        stack.extend(n.children)
    return None


def replace_function(source: str, name: str, new_function: str) -> str | None:
    """Splice `new_function` in place of method `name`. Returns the new source, or None if not found.
    Indentation of the replacement is matched to the original method's column."""
    span = find_function_span(source, name)
    if span is None:
        return None
    start, end = span
    src = source.encode()
    col = 0
    i = start
    while i > 0 and src[i - 1:i] in (b" ", b"\t"):
        col += 1
        i -= 1
    body = _reindent(new_function, col)
    return src[:start].decode() + body + src[end:].decode()


def _reindent(text: str, col: int) -> str:
    """Match a model-returned method to the original's indentation. `src[:start]` already supplies the
    first line's indent, so the first line sits at column 0 here; later lines get `col` more spaces."""
    dedented = textwrap.dedent(text.strip("\n")).split("\n")
    pad = " " * col
    out = [dedented[0]]
    for ln in dedented[1:]:
        out.append(pad + ln if ln.strip() else "")
    return "\n".join(out)
