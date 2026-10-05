"""
Autonomous mode — a small code index over the snapshot, built with Tree-sitter.

It answers the questions harness synthesis needs and nothing more:

  * which functions exist, where, with what parameters, and are they static;
  * who calls a given function, with which argument expressions;
  * inside each caller, which local arrays have a literal size
    (`char buf[64]` → 64), so a call `f(buf, ...)` tells us the buffer size a
    real caller hands this function;
  * which header declares a function, so a harness can include it instead of
    re-declaring it.

Everything is derived from the snapshot's text. Nothing here compiles or runs
code.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.context_engine.tree_sitter_extractor import ContextExtractor


@dataclass
class Param:
    text: str            # the declaration as written: "const unsigned char *buf"
    name: str            # "buf" ("" for an unnamed or `void` parameter)
    type: str            # "const unsigned char *"
    pointer_depth: int   # number of `*` (array parameters count as one)

    @property
    def base(self) -> str:
        """Type without qualifiers or pointer marks: "unsigned char"."""
        t = re.sub(r"\b(const|volatile|restrict|__restrict|register)\b", " ", self.type)
        t = t.replace("*", " ").replace("[", " ").replace("]", " ")
        return " ".join(t.split())


@dataclass
class Function:
    name: str
    file: str            # relative to the snapshot root (POSIX)
    start_line: int
    end_line: int
    is_static: bool
    return_type: str
    params: list[Param]
    signature: str       # the definition up to (not including) the body
    variadic: bool = False


@dataclass
class CallSite:
    caller: str          # name of the enclosing function ("" at file scope)
    callee: str
    file: str
    line: int
    args: list[str]
    # literal-size local arrays visible in the caller: name -> size
    arrays: dict[str, int] = field(default_factory=dict)


_DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+\(?\s*(\d+)\s*[uUlL]*\s*\)?\s*$", re.M)


class CodeIndex:
    def __init__(self, root: Path, sources: list[str], headers: Optional[list[str]] = None):
        self.root = root
        self.extractor = ContextExtractor()
        self.functions: dict[str, list[Function]] = {}
        self.calls: dict[str, list[CallSite]] = {}
        self.macros: dict[str, int] = {}
        self._headers = headers if headers is not None else [
            p.relative_to(root).as_posix() for p in root.rglob("*.h") if p.is_file()]
        for h in self._headers:
            self._read_macros(root / h)
        for rel in sources:
            self._index_file(rel)

    # -- queries -------------------------------------------------------------

    def function(self, name: str, file: Optional[str] = None) -> Optional[Function]:
        cands = self.functions.get(name, [])
        if file:
            for f in cands:
                if f.file == file:
                    return f
        return cands[0] if cands else None

    def function_at(self, file: str, line: int) -> Optional[Function]:
        for funcs in self.functions.values():
            for f in funcs:
                if f.file == file and f.start_line <= line <= f.end_line:
                    return f
        return None

    def callers_of(self, name: str) -> list[CallSite]:
        return self.calls.get(name, [])

    def header_declaring(self, name: str) -> Optional[str]:
        """A header (relative path) that declares `name(`, preferring top-level ones."""
        pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
        found = []
        for h in self._headers:
            try:
                text = (self.root / h).read_text(errors="replace")
            except OSError:
                continue
            if pattern.search(text):
                found.append(h)
        found.sort(key=lambda h: (h.count("/"), len(h)))
        return found[0] if found else None

    # -- indexing --------------------------------------------------------------

    def _read_macros(self, path: Path) -> None:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return
        for name, value in _DEFINE.findall(text):
            self.macros.setdefault(name, int(value))

    def _index_file(self, rel: str) -> None:
        path = self.root / rel
        try:
            data = path.read_bytes()
        except OSError:
            return
        self._read_macros(path)
        tree = self.extractor.c_parser.parse(data)
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "function_definition":
                fn = self._function(node, data, rel)
                if fn:
                    self.functions.setdefault(fn.name, []).append(fn)
                    self._collect_calls(node, data, rel, fn.name)
                continue
            stack.extend(reversed(node.children))   # pop() is LIFO: keep source order

    def _function(self, node, data: bytes, rel: str) -> Optional[Function]:
        name = self.extractor._get_function_name(node)
        if not name or name == "unknown":
            return None
        declarator = self.extractor._find_function_declarator(node)
        if declarator is None:
            return None
        body = node.child_by_field_name("body")
        sig_end = body.start_byte if body is not None else node.end_byte
        signature = data[node.start_byte:sig_end].decode("utf-8", "replace").strip()
        is_static = any(
            c.type == "storage_class_specifier" and c.text and c.text.decode() == "static"
            for c in node.children
        )
        type_node = node.child_by_field_name("type")
        return_type = type_node.text.decode("utf-8", "replace") if type_node is not None and type_node.text else "int"
        # Pointer-returning functions: the `*` sits in the declarator chain.
        decl = node.child_by_field_name("declarator")
        while decl is not None and decl.type == "pointer_declarator":
            return_type += " *"
            decl = decl.child_by_field_name("declarator")

        params, variadic = [], False
        plist = declarator.child_by_field_name("parameters")
        for p in (plist.children if plist is not None else []):
            if p.type == "variadic_parameter" or (p.text and p.text.decode() == "..."):
                variadic = True
                continue
            if p.type != "parameter_declaration":
                continue
            params.append(self._param(p))
        if len(params) == 1 and params[0].type.strip() == "void" and not params[0].name:
            params = []
        return Function(
            name=name, file=rel, start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1, is_static=is_static,
            return_type=" ".join(return_type.split()), params=params,
            signature=signature, variadic=variadic,
        )

    @staticmethod
    def _param(p) -> Param:
        text = " ".join(p.text.decode("utf-8", "replace").split()) if p.text else ""
        depth, name = 0, ""
        node = p.child_by_field_name("declarator")
        while node is not None:
            if node.type == "pointer_declarator":
                depth += 1
                node = node.child_by_field_name("declarator")
            elif node.type == "array_declarator":
                depth += 1
                node = node.child_by_field_name("declarator")
            elif node.type in ("identifier",):
                name = node.text.decode() if node.text else ""
                break
            elif node.type in ("parenthesized_declarator", "function_declarator"):
                depth += 1           # function pointer: treated as "other"
                name = ""
                break
            else:
                break
        type_text = text
        if name:
            idx = type_text.rfind(name)
            if idx >= 0:
                type_text = type_text[:idx] + type_text[idx + len(name):]
        type_text = re.sub(r"\[[^\]]*\]", "*", type_text)
        return Param(text=text, name=name, type=" ".join(type_text.split()), pointer_depth=depth)

    def _collect_calls(self, func_node, data: bytes, rel: str, caller: str) -> None:
        arrays: dict[str, int] = {}
        stack = [func_node]
        calls = []
        while stack:
            node = stack.pop()
            if node.type == "declaration":
                for d in node.children:
                    target = d.child_by_field_name("declarator") if d.type == "init_declarator" else d
                    if target is not None and target.type == "array_declarator":
                        ident = target.child_by_field_name("declarator")
                        size = target.child_by_field_name("size")
                        if ident is not None and size is not None and ident.text and size.text:
                            n = self._int_value(size.text.decode())
                            if n:
                                arrays[ident.text.decode()] = n
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                if fn is not None and fn.type == "identifier" and fn.text:
                    arg_texts = []
                    for a in (args.children if args is not None else []):
                        if a.type in ("(", ")", ","):
                            continue
                        arg_texts.append(" ".join(a.text.decode("utf-8", "replace").split())
                                         if a.text else "")
                    calls.append((fn.text.decode(), node.start_point[0] + 1, arg_texts))
            stack.extend(reversed(node.children))   # pop() is LIFO: keep source order
        for callee, line, arg_texts in calls:
            self.calls.setdefault(callee, []).append(
                CallSite(caller=caller, callee=callee, file=rel, line=line,
                         args=arg_texts, arrays=dict(arrays)))

    def _int_value(self, text: str) -> Optional[int]:
        text = text.strip().rstrip("uUlL")
        if re.fullmatch(r"\d+", text):
            return int(text)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
            return int(text, 16)
        return self.macros.get(text)
