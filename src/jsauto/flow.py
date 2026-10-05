"""
Generic taint-flow analysis for JavaScript / Node web applications.

The algorithm knows nothing about any application. It works from structure:

  1. ENTRY POINTS. A function is an entry point if it is registered on a route
     (`x.get("/path", handler)`, a `route({path, handler})` object), or if it reads an HTTP-looking
     property (query, body, params, ...) off one of its own parameters. The parameter is the
     request *by role*, whatever it is called, and whichever framework it comes from.
  2. TAINT SLICE. From each entry point, user data is followed through variables, destructuring,
     template strings, concatenation and calls. Calls into other functions of the repository
     (resolved by name, across files) are followed too, so a route that hands a value to a data
     layer is analysed through to the query it builds.
  3. SINKS. A call that receives tainted data is classified by DATA, not code: the module the callee
     was imported from (`require`/`import`), its function name, and the shape of the call are matched
     against config/js_knowledge.json. A call that file does not recognise is not guessed at and not
     dropped: it goes to a classifier (the model, when one is configured), the answer is cached, and
     calls left unclassified are reported as such.

Everything here yields CANDIDATES. A dynamic probe against a running instance is what confirms one.
Precision limits are stated in the evidence: confidence is lower when the entry point was inferred
only from property access, and when a sink was classified by the model.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import tree_sitter_javascript
from tree_sitter import Language, Parser

KNOWLEDGE_PATH = Path(__file__).resolve().parents[2] / "config" / "js_knowledge.json"
SOURCE_SUFFIXES = (".js", ".mjs", ".cjs")
SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "coverage", ".git", "test", "tests", "__tests__",
             "spec", "cypress", "assets", "public", "static"}
MAX_DEPTH = 4
MAX_FILE_BYTES = 800_000

# NB: Tree-sitter also emits the bare `function` KEYWORD as a token of type "function"; it is not a
# function node and must not be listed (it shares its start byte with the declaration it begins).
_FUNCTION_TYPES = {"function_declaration", "generator_function_declaration", "function_expression",
                   "arrow_function", "method_definition"}


def load_knowledge(path: Path = KNOWLEDGE_PATH) -> dict:
    return json.loads(Path(path).read_text())


# -- results ------------------------------------------------------------------------------------------

@dataclass
class Sink:
    klass: str
    cwe: str
    file: str
    line: int
    function: str                 # the function that contains the sink (where a patch goes)
    callee: str
    arg_index: int
    tainted_expr: str
    chain: list = field(default_factory=list)     # entry -> ... -> sink function
    entry: dict = field(default_factory=dict)     # {"function","file","route","via"}
    confidence: str = "medium"
    classified_by: str = "catalog"                 # catalog | model
    fields: list = field(default_factory=list)     # [[location, field], ...] of the request that fed the sink


@dataclass
class Unknown:
    callee: str
    module: str
    file: str
    line: int
    function: str
    arg_index: int
    tainted_expr: str
    snippet: str
    chain: list
    entry: dict
    fn: object = None
    node: object = None


@dataclass
class Fn:
    name: str
    file: str
    node: object
    params: list
    start: int
    end: int


# -- project model ------------------------------------------------------------------------------------

class Project:
    def __init__(self, root: Path, knowledge: Optional[dict] = None):
        self.root = Path(root).resolve()
        self.k = knowledge or load_knowledge()
        self.parser = Parser(Language(tree_sitter_javascript.language()))
        self.sources: dict[str, bytes] = {}
        self.trees: dict[str, object] = {}
        self.imports: dict[str, dict[str, str]] = {}          # file -> local name -> module
        self.functions: dict[str, list[Fn]] = {}               # simple name -> definitions
        self.by_node: dict[tuple, Fn] = {}
        self.routes: dict[tuple, dict] = {}                    # (file, start line) -> {"method","path"}
        self.registered: set[tuple] = set()                    # fn keys registered on a route
        self.ambiguous: set[tuple] = set()                     # registered by a name that several functions share
        self._san = [re.compile(p) for p in self.k["sanitizers"]]
        self._load()

    # --- loading
    def _load(self) -> None:
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            rel = path.relative_to(self.root)
            if any(part in SKIP_DIRS for part in rel.parts[:-1]) or path.stat().st_size > MAX_FILE_BYTES:
                continue
            src = path.read_bytes()
            key = rel.as_posix()
            self.sources[key] = src
            self.trees[key] = self.parser.parse(src)
        for f, tree in self.trees.items():
            self.imports[f] = self._collect_imports(f, tree.root_node)
            self._collect_functions(f, tree.root_node)
        for f, tree in self.trees.items():
            self._collect_routes(f, tree.root_node)

    def text(self, f: str, node) -> str:
        return self.sources[f][node.start_byte:node.end_byte].decode("utf-8", "replace")

    @staticmethod
    def _walk(node):
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.children))

    def _collect_imports(self, f: str, root) -> dict:
        out = {}
        for n in self._walk(root):
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                if fn is not None and self.text(f, fn) == "require" and args is not None and args.named_children:
                    a = args.named_children[0]
                    if a.type == "string":
                        module = self.text(f, a).strip("'\"`")
                        parent = n.parent
                        # const x = require("m")      const {a, b: c} = require("m")      const x = require("m").y
                        while parent is not None and parent.type in ("member_expression", "parenthesized_expression"):
                            parent = parent.parent
                        if parent is not None and parent.type == "variable_declarator":
                            name = parent.child_by_field_name("name")
                            if name is not None:
                                for ident in self._pattern_names(f, name):
                                    out[ident] = module
            elif n.type == "import_statement":
                src = n.child_by_field_name("source")
                if src is not None:
                    module = self.text(f, src).strip("'\"`")
                    for c in self._walk(n):
                        if c.type == "identifier" and c.parent is not None and c.parent.type in (
                                "import_clause", "namespace_import", "import_specifier"):
                            out[self.text(f, c)] = module
        return out

    def _pattern_names(self, f: str, node) -> list[str]:
        if node.type == "identifier":
            return [self.text(f, node)]
        names = []
        for c in self._walk(node):
            if c.type in ("shorthand_property_identifier_pattern", "identifier") and c is not node:
                if c.type == "identifier" and c.parent is not None and c.parent.type == "pair_pattern" \
                        and c.parent.child_by_field_name("key") is c:
                    continue
                names.append(self.text(f, c))
        return names

    def _params(self, f: str, node) -> list:
        p = node.child_by_field_name("parameters")
        if p is None:
            single = node.child_by_field_name("parameter")
            return [self.text(f, single)] if single is not None and single.type == "identifier" else []
        out = []
        for c in p.named_children:
            if c.type == "identifier":
                out.append(self.text(f, c))
            elif c.type in ("assignment_pattern", "rest_pattern"):
                first = next((x for x in c.named_children if x.type == "identifier"), None)
                out.append(self.text(f, first) if first is not None else "")
            else:
                out.append("")                                  # destructured: positional, unnamed
        return out

    def _function_name(self, f: str, node) -> str:
        own = node.child_by_field_name("name")
        if own is not None:
            return self.text(f, own)
        parent = node.parent
        if parent is None:
            return ""
        if parent.type == "variable_declarator":
            n = parent.child_by_field_name("name")
            return self.text(f, n) if n is not None and n.type == "identifier" else ""
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            if left is not None and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                return self.text(f, prop) if prop is not None else ""
            return self.text(f, left) if left is not None else ""
        if parent.type == "pair":
            key = parent.child_by_field_name("key")
            return self.text(f, key) if key is not None else ""
        return ""

    def _collect_functions(self, f: str, root) -> None:
        for n in self._walk(root):
            if n.type not in _FUNCTION_TYPES:
                continue
            name = self._function_name(f, n)
            fn = Fn(name=name or f"<anonymous@{n.start_point[0] + 1}>", file=f, node=n,
                    params=self._params(f, n), start=n.start_point[0] + 1, end=n.end_point[0] + 1)
            self.by_node[(f, n.start_byte)] = fn
            if name:
                self.functions.setdefault(name, []).append(fn)

    # --- routes
    def _collect_routes(self, f: str, root) -> None:
        verbs = set(self.k["route_verbs"])
        for n in self._walk(root):
            if n.type != "call_expression":
                continue
            callee = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if callee is None or args is None or callee.type != "member_expression":
                continue
            prop = callee.child_by_field_name("property")
            method = self.text(f, prop) if prop is not None else ""
            if method not in verbs:
                continue
            named = args.named_children
            path_arg = next((a for a in named if a.type in ("string", "template_string")), None)
            if method == "route" and named and named[0].type == "object":        # hapi style
                obj = {self.text(f, p.child_by_field_name("key")).strip("'\""): p.child_by_field_name("value")
                       for p in named[0].named_children if p.type == "pair"}
                if "handler" in obj and "path" in obj:
                    meth = self.text(f, obj["method"]).strip("'\"") if "method" in obj else "ALL"
                    self._register(f, obj["handler"], meth, self.text(f, obj["path"]).strip("'\"`"))
                continue
            if path_arg is None:
                continue
            path = self.text(f, path_arg).strip("'\"`")
            if not path.startswith(("/", "*")):
                continue
            for a in named:
                if a is path_arg:
                    continue
                self._register(f, a, method.upper(), path)

    def _register(self, f: str, node, method: str, path: str) -> None:
        targets = []
        if node.type in _FUNCTION_TYPES:
            fn = self.by_node.get((f, node.start_byte))
            if fn:
                targets.append(fn)
        elif node.type in ("identifier", "member_expression"):
            simple = self.text(f, node).split(".")[-1]
            targets += self.functions.get(simple, [])
        for fn in targets:
            key = (fn.file, fn.start)
            if len(targets) > 1:
                self.ambiguous.add(key)
            self.registered.add(key)
            self.routes[key] = {"method": method, "path": path}

    # --- helpers for analysis
    def is_sanitizer(self, callee_text: str) -> bool:
        return any(p.search(callee_text) for p in self._san)


# -- taint walk -----------------------------------------------------------------------------------------

class Analyzer:
    def __init__(self, project: Project, classifier: Optional[Callable] = None, unknown_cap: int = 40):
        self.p = project
        self.k = project.k
        self.props = set(self.k["request_properties"])
        self.ignore_roots = set(self.k["ignore_roots"])
        self.ignore_methods = set(self.k["ignore_methods"])
        self.sinks: list[Sink] = []
        self.unknown: list[Unknown] = []
        self.entry_points: list[dict] = []
        self.classifier = classifier
        self.classifier_errors: list[str] = []     # a failing model must be visible, not a silent "no sink"
        self.classifier_calls = 0
        self.unknown_cap = unknown_cap
        self._seen: set = set()

    # --- entry points
    def run(self) -> None:
        cands: list[Fn] = [fn for fns in self.p.functions.values() for fn in fns]
        # anonymous inline handlers registered on a route
        for key in self.p.registered:
            fn = self.p.by_node.get(self._key_to_node(key))
            if fn and fn.name.startswith("<anonymous"):
                cands.append(fn)
        # Route-registered handlers first. The same sink is often reachable both from a route and from
        # a helper that merely reads a request property; the first analysis to report it wins, and the
        # route-derived one is the better evidence (it knows the route and the full call chain).
        cands.sort(key=lambda fn: (fn.file, fn.start) not in self.p.registered)
        for fn in cands:
            self._maybe_entry(fn)
        if self.classifier is not None:
            self._classify_unknown()

    def _key_to_node(self, key):
        f, start_line = key
        for (ff, sb), fn in self.p.by_node.items():
            if ff == f and fn.start == start_line:
                return (ff, sb)
        return None

    def _request_params(self, fn: Fn) -> set:
        """Parameters that act as an HTTP request: a request property is read off them."""
        out = set()
        names = [n for n in fn.params if n]
        body = fn.node.child_by_field_name("body")
        if body is None:
            return out
        for n in self.p._walk(body):
            if n.type == "member_expression":
                obj = n.child_by_field_name("object")
                prop = n.child_by_field_name("property")
                if obj is None or prop is None:
                    continue
                root = self._root(fn.file, obj)
                # `req.query.x`, and Koa's `ctx.request.body` (one hop through a wrapper property)
                if root in names and self.p.text(fn.file, prop) in self.props:
                    out.add(root)
                elif root in names and obj.type == "member_expression" and \
                        self.p.text(fn.file, prop) in self.props:
                    out.add(root)
        return out

    def _request_fields(self, fn: Fn, reqs: set) -> list:
        """
        [[location, field], ...] the handler reads off its request parameter(s), in order. A probe has to
        send ALL of them: a handler that reads three fields and gets one fails its own validation before
        it reaches the vulnerable line, which looks exactly like "not vulnerable".
        """
        body = fn.node.child_by_field_name("body")
        if body is None or not reqs:
            return []
        text = self.p.text(fn.file, body)
        locs = "|".join(sorted(self.props & {"query", "body", "params", "payload"}))
        found, seen = [], set()
        for r in sorted(reqs):
            for m in re.finditer(r"\b%s\.(%s)\.([A-Za-z_$][\w$]*)" % (re.escape(r), locs), text):
                key = (m.group(1), m.group(2))
                if key not in seen:
                    seen.add(key)
                    found.append(list(key))
        return found

    def _root(self, f: str, node) -> str:
        while node is not None and node.type in ("member_expression", "subscript_expression", "call_expression",
                                                 "await_expression", "parenthesized_expression"):
            nxt = node.child_by_field_name("object") or node.child_by_field_name("function") or \
                (node.named_children[0] if node.named_children else None)
            if nxt is node:
                break
            node = nxt
        return self.p.text(f, node) if node is not None and node.type in ("identifier", "this") else ""

    def _maybe_entry(self, fn: Fn) -> None:
        key = (fn.file, fn.start)
        reqs = self._request_params(fn)
        registered = key in self.p.registered
        if not reqs and registered and fn.params and key not in self.p.ambiguous:
            reqs = {fn.params[0]} if fn.params[0] else set()     # a registered handler: first param is the request
        if not reqs:
            return
        route = self.p.routes.get(key)
        entry = {"function": fn.name, "file": fn.file, "line": fn.start,
                 "route": route, "via": "route" if registered else "request-property-access",
                 "request_param": sorted(reqs), "request_fields": self._request_fields(fn, reqs)}
        self.entry_points.append(entry)
        self._analyze(fn, req_params=set(reqs), tainted=set(), chain=[f"{fn.file}:{fn.name}"],
                      entry=entry, depth=0, visited=frozenset({key}))

    # --- taint
    def _is_tainted(self, f: str, node, req_params: set, tainted: set) -> bool:
        t = node.type
        if t in _FUNCTION_TYPES:
            return False
        if t == "identifier":
            return self.p.text(f, node) in tainted
        if t == "member_expression":
            root = self._root(f, node)
            chain = self._property_chain(f, node)
            if root in req_params and any(c in self.props for c in chain):
                return True
            if root in tainted:
                return True
            obj = node.child_by_field_name("object")
            return obj is not None and self._is_tainted(f, obj, req_params, tainted)
        if t == "call_expression":
            callee = node.child_by_field_name("function")
            ctext = self.p.text(f, callee) if callee is not None else ""
            if self.p.is_sanitizer(ctext):
                return False
            args = node.child_by_field_name("arguments")
            if args is not None and any(self._is_tainted(f, a, req_params, tainted) for a in args.named_children):
                return True
            return callee is not None and callee.type == "member_expression" and \
                self._is_tainted(f, callee.child_by_field_name("object"), req_params, tainted)
        return any(self._is_tainted(f, c, req_params, tainted) for c in node.named_children)

    def _property_chain(self, f: str, node) -> list:
        out = []
        while node is not None and node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None:
                out.append(self.p.text(f, prop))
            node = node.child_by_field_name("object")
        return out

    def _fields_in(self, text: str) -> list:
        """
        [[location, field], ...] of the request that an expression's text draws on: direct reads such as
        `req.query.url`, plus the origin of every tainted variable named in it. This is how a sink argument
        that is just a variable (`url`) still says which request fields feed it, which a probe needs.
        """
        cur = self._cur
        locs = "|".join(sorted(self.props & {"query", "body", "params", "payload"}))
        found, seen = [], set()

        def add(pair):
            if pair not in seen:
                seen.add(pair)
                found.append(list(pair))
        for r in sorted(cur["reqs"]):
            for m in re.finditer(r"\b%s\.(%s)\.([A-Za-z_$][\w$]*)" % (re.escape(r), locs), text):
                add((m.group(1), m.group(2)))
        for ident in re.findall(r"[A-Za-z_$][\w$]*", text):
            for loc, name in cur["origin"].get(ident, []):
                add((loc, name))
        return found

    def _analyze(self, fn: Fn, req_params: set, tainted: set, chain: list, entry: dict,
                 depth: int, visited: frozenset, origin: Optional[dict] = None) -> None:
        f = fn.file
        body = fn.node.child_by_field_name("body")
        if body is None:
            return
        params = set(p for p in fn.params if p)
        tainted = set(tainted)
        outer = getattr(self, "_cur", None)
        self._cur = {"origin": dict(origin or {}), "reqs": set(req_params)}
        try:
            # ordered walk: assignments feed later calls
            for n in self.p._walk(body):
                t = n.type
                if t == "variable_declarator":
                    val = n.child_by_field_name("value")
                    name = n.child_by_field_name("name")
                    if val is not None and name is not None and self._is_tainted(f, val, req_params, tainted):
                        names = self.p._pattern_names(f, name)
                        tainted.update(names)
                        fields = self._fields_in(self.p.text(f, val))
                        for nm in names:
                            self._cur["origin"][nm] = fields
                        # `const { name } = req.query`: the text names no field, the pattern does
                        m = re.fullmatch(r"(\w+)\.(query|body|params|payload)", self.p.text(f, val).strip())
                        if m and m.group(1) in req_params and name.type == "object_pattern":
                            for c in name.named_children:
                                if c.type == "shorthand_property_identifier_pattern":
                                    nm = self.p.text(f, c)
                                    self._cur["origin"][nm] = [[m.group(2), nm]]
                elif t == "assignment_expression":
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    if left is not None and right is not None and self._is_tainted(f, right, req_params, tainted):
                        tainted.add(self.p.text(f, left))
                        self._cur["origin"][self.p.text(f, left)] = self._fields_in(self.p.text(f, right))
                elif t == "pair":
                    self._check_key_sink(fn, n, req_params, tainted, chain, entry)
                elif t == "call_expression":
                    self._check_call(fn, n, req_params, tainted, params, chain, entry, depth, visited)
                elif t == "new_expression":
                    self._check_new(fn, n, req_params, tainted, chain, entry)
        finally:
            self._cur = outer

    # --- sinks
    def _confidence(self, entry: dict, base: str) -> str:
        if entry["via"] != "route" and base == "high":
            return "medium"
        if entry["via"] != "route":
            return "low"
        return base

    def _emit(self, fn: Fn, node, spec: dict, callee: str, idx: int, expr: str, chain: list, entry: dict,
              by: str = "catalog") -> None:
        inner = self._innermost(fn, node)
        key = (fn.file, node.start_point[0] + 1, spec["class"], callee)
        if key in self._seen:
            return
        self._seen.add(key)
        self.sinks.append(Sink(
            klass=spec["class"], cwe=spec.get("cwe", ""), file=fn.file, line=node.start_point[0] + 1,
            function=inner.name, callee=callee, arg_index=idx, tainted_expr=expr[:120], chain=list(chain),
            entry=entry, confidence=self._confidence(entry, spec.get("confidence", "high")),
            classified_by=by, fields=self._fields_in(expr) if getattr(self, "_cur", None) else []))

    def _innermost(self, fn: Fn, node) -> Fn:
        """The innermost function (named or anonymous) containing `node`; falls back to `fn`."""
        cur = node
        while cur is not None:
            if cur.type in _FUNCTION_TYPES:
                hit = self.p.by_node.get((fn.file, cur.start_byte))
                if hit is not None:
                    return hit
            cur = cur.parent
        return fn

    def _check_key_sink(self, fn, node, req_params, tainted, chain, entry) -> None:
        key = node.child_by_field_name("key")
        val = node.child_by_field_name("value")
        if key is None or val is None:
            return
        k = self.p.text(fn.file, key).strip("'\"")
        for spec in self.k["sink_keys"]:
            if k == spec["key"] and self._is_tainted(fn.file, val, req_params, tainted):
                self._emit(fn, node, spec, k, 0, self.p.text(fn.file, val), chain, entry)

    def _check_new(self, fn, node, req_params, tainted, chain, entry) -> None:
        ctor = node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments")
        if ctor is None or args is None:
            return
        name = self.p.text(fn.file, ctor)
        for spec in self.k["global_sinks"]:
            if re.search(spec["callee"], name):
                for i, a in enumerate(args.named_children):
                    if self._is_tainted(fn.file, a, req_params, tainted):
                        self._emit(fn, node, spec, "new " + name, i, self.p.text(fn.file, a), chain, entry)

    def _arg_matches(self, spec: dict, i: int, n_args: int) -> bool:
        wanted = spec.get("args", [0])
        return i in wanted or (-1 in wanted and i == n_args - 1)

    def _check_call(self, fn, node, req_params, tainted, params, chain, entry, depth, visited) -> None:
        f = fn.file
        callee = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if callee is None or args is None:
            return
        argl = args.named_children
        tainted_idx = [i for i, a in enumerate(argl) if self._is_tainted(f, a, req_params, tainted)]
        # passing the request object itself into another function hands over the role
        req_idx = [i for i, a in enumerate(argl) if a.type == "identifier" and self.p.text(f, a) in req_params]
        if not tainted_idx and not req_idx:
            return
        ctext = self.p.text(f, callee)
        root = self._root(f, callee)
        last = ctext.split(".")[-1].split("(")[0]
        module = self.p.imports.get(f, {}).get(root, "")
        if module.startswith((".", "/")):                       # require("./dao"): the repository, not a package
            module = ""

        # 1. a call into the repository: follow it
        defs = [d for d in self.p.functions.get(last, []) if d.node is not fn.node] if module == "" else []
        if ctext == root and root in params and not defs:
            return                                              # calling a callback parameter: callback(err, x)
        if defs and depth < MAX_DEPTH:
            for d in defs[:3]:
                key = (d.file, d.start)
                if key in visited:
                    continue
                new_t = {d.params[i] for i in tainted_idx if i < len(d.params) and d.params[i]}
                new_origin = {d.params[i]: self._fields_in(self.p.text(f, argl[i]))
                              for i in tainted_idx if i < len(d.params) and d.params[i]}
                new_r = {d.params[i] for i in req_idx if i < len(d.params) and d.params[i]}
                if new_t or new_r:
                    self._analyze(d, new_r, new_t, chain + [f"{d.file}:{d.name}"], entry, depth + 1,
                                  visited | {key}, origin=new_origin)
            return

        # 2. catalogued sinks (by imported module, global name, or response method)
        matched = False
        for spec in self.k["sink_modules"]:
            if module in spec["modules"] and (spec["functions"] is None and ctext == root
                                              or spec["functions"] is not None and re.match(spec["functions"], last)):
                matched = True
                for i in tainted_idx:
                    if self._arg_matches(spec, i, len(argl)):
                        self._emit(fn, node, spec, ctext, i, self.p.text(f, argl[i]), chain, entry)
        if module == "" or root == ctext:
            for spec in self.k["global_sinks"]:
                if re.match(spec["callee"], ctext):
                    matched = True
                    for i in tainted_idx:
                        if self._arg_matches(spec, i, len(argl)) and (
                                not spec.get("only_if_string") or argl[i].type in ("string", "template_string",
                                                                                   "binary_expression")):
                            self._emit(fn, node, spec, ctext, i, self.p.text(f, argl[i]), chain, entry)
        if root in fn.params:                                    # method on a parameter, e.g. the response
            for spec in self.k["response_sinks"]:
                if re.match(spec["methods"], last):
                    matched = True
                    for i in tainted_idx:
                        if self._arg_matches(spec, i, len(argl)):
                            self._emit(fn, node, spec, ctext, i, self.p.text(f, argl[i]), chain, entry)
        if matched:
            return

        # 3. not recognised: ignore the plainly harmless, otherwise ask the classifier
        if root in self.ignore_roots or last in self.ignore_methods or not tainted_idx \
                or self.p.is_sanitizer(ctext) or (root in params and ctext == root):
            return
        if len(self.unknown) >= self.unknown_cap:
            return
        line = node.start_point[0] + 1
        src_lines = self.p.sources[f].decode("utf-8", "replace").splitlines()
        snippet = "\n".join(src_lines[max(0, line - 3): line + 2])
        self.unknown.append(Unknown(callee=ctext, module=module, file=f, line=line, function=fn.name,
                                    arg_index=tainted_idx[0], tainted_expr=self.p.text(f, argl[tainted_idx[0]])[:120],
                                    snippet=snippet, chain=list(chain), entry=entry, fn=fn, node=node))

    # --- classifier for calls the knowledge file does not cover
    def _classify_unknown(self) -> None:
        cache: dict[tuple, Optional[dict]] = {}
        for u in self.unknown:
            key = (u.module, u.callee.split(".")[-1])
            if key not in cache:
                try:
                    self.classifier_calls += 1
                    cache[key] = self.classifier(u)
                except Exception as e:
                    cache[key] = None
                    self.classifier_errors.append(f"{u.callee}: {type(e).__name__}: {str(e)[:140]}")
            verdict = cache[key]
            if verdict and verdict.get("sink"):
                fn, node = u.fn, u.node
                if fn is None or node is None:
                    continue
                self._emit(fn, node, {"class": verdict["class"], "cwe": verdict.get("cwe", ""),
                                      "confidence": "low"}, u.callee, u.arg_index, u.tainted_expr,
                           u.chain, u.entry, by="model")
        self.unclassified = [u for u in self.unknown
                             if not (cache.get((u.module, u.callee.split(".")[-1])) or {}).get("sink")]


def analyze(root: Path, classifier: Optional[Callable] = None, knowledge: Optional[dict] = None) -> Analyzer:
    p = Project(root, knowledge)
    a = Analyzer(p, classifier)
    a.run()
    a.severity = p.k.get("severity", {})
    if not hasattr(a, "unclassified"):
        a.unclassified = list(a.unknown)
    return a
