"""Step 1: deterministic route map (entry points) from source, per framework. No LLM, no network.

    python -m exp.scripts.route_map <target-dir> <out.json> [--openapi <spec.yml>]

Frameworks: OpenAPI/connexion (operationId -> function), Spring (any annotation named *Mapping on a method of a *Controller class,
including custom ones; string constants resolved), Express (app/router .get|.post|... with a "/..." path, middleware chain + handler),
Flask (@x.route / @x.get ... decorators). Each route: {framework, method, path, file, function, params, param_annotations, middleware}.
The Joern scripts use (file, function) as taint-source entry points; the live checker uses (method, path, params) as the probe list.
"""
import ast, json, re, sys
from pathlib import Path

import tree_sitter_java, tree_sitter_javascript
from tree_sitter import Language, Parser
from ruamel.yaml import YAML

JAVA = Parser(Language(tree_sitter_java.language()))
JS = Parser(Language(tree_sitter_javascript.language()))
SKIP = ("node_modules", "/test/", "/tests/", "/build/", "/.git/", "/frontend/", "/public/", "/artifacts/",
        "/.venv/", "/venv/", "/env/", "/site-packages/", "/__pycache__/")
def skipped(f, root): return any(s in "/" + str(f.relative_to(root)).replace("\\", "/") for s in SKIP)

def txt(src, n): return src[n.start_byte:n.end_byte].decode("utf-8", "replace")

# ---------------- OpenAPI ----------------
def openapi_routes(spec_path, root):
    spec = YAML(typ="safe").load(Path(spec_path).read_text()); out = []
    for path, item in (spec.get("paths") or {}).items():
        for method, op in item.items():
            if method not in ("get", "post", "put", "delete", "patch") or not isinstance(op, dict): continue
            oid = op.get("operationId", ""); mod, _, fn = oid.rpartition(".")
            f = str(Path(*mod.split("."))) + ".py" if mod else ""
            params = [p["name"] for p in (op.get("parameters") or []) if isinstance(p, dict) and "name" in p]
            out.append({"framework": "openapi", "method": method.upper(), "path": path, "file": f, "function": fn, "params": params, "param_annotations": [],
                        "middleware": [], "auth": bool(op.get("security")), "body": "requestBody" in op})
    return out

# ---------------- Spring ----------------
def java_constants(files):
    c = {}
    for f in files:
        s = f.read_text(errors="ignore")
        cls = f.stem
        for m in re.finditer(r'\bString\s+(\w+)\s*=\s*"([^"]*)"\s*;', s):         # class constants and interface constants
            c[f"{cls}.{m.group(1)}"] = m.group(2); c.setdefault(m.group(1), m.group(2))
    return c

def ann_value(src, ann, consts):
    t = txt(src, ann)
    m = re.search(r'\b(?:value|path)\s*=\s*\{?\s*("([^"]*)"|[\w.]+)', t) or re.search(r'\(\s*\{?\s*("([^"]*)"|[\w.]+)\s*[,)}]', t)
    if not m: return ""
    return m.group(2) if m.group(2) is not None else consts.get(m.group(1), consts.get(m.group(1).split(".")[-1], ""))

def spring_routes(root):
    files = [f for f in Path(root).rglob("*.java") if not skipped(f, Path(root))]
    consts = java_constants(files); out = []
    for f in files:
        src = f.read_bytes(); stack = [JAVA.parse(src).root_node]; classes = []
        while stack:
            n = stack.pop(); stack.extend(n.children)
            if n.type == "class_declaration": classes.append(n)
        for cls in classes:
            mods = [c for c in cls.children if c.type == "modifiers"]
            anns = [a for m in mods for a in m.children if a.type in ("annotation", "marker_annotation")]
            def aname(a): return txt(src, a.child_by_field_name("name"))
            ctl = [a for a in anns if aname(a).endswith("Controller")]
            if not ctl: continue
            base = ""
            for a in anns:
                if aname(a).endswith("Mapping") or aname(a).endswith("Controller"):
                    v = ann_value(src, a, consts)
                    if v: base = v; break
            body = cls.child_by_field_name("body")
            for m in (body.children if body else []):
                if m.type != "method_declaration": continue
                mm = [c for c in m.children if c.type == "modifiers"]
                manns = [a for x in mm for a in x.children if a.type in ("annotation", "marker_annotation")]
                maps = [a for a in manns if aname(a).endswith("Mapping")]
                if not maps: continue
                mp = maps[0]; nm = aname(mp); mv = ann_value(src, mp, consts)
                http = re.sub("Mapping$", "", nm).upper() if nm.endswith("Mapping") and nm not in ("RequestMapping",) else ""
                mt = re.search(r"RequestMethod\.(\w+)", txt(src, mp)); http = mt.group(1) if mt else http
                if not http or http in ("VULNERABLEAPPREQUEST",) or "REQUEST" in http: http = http if http in ("GET", "POST", "PUT", "DELETE", "PATCH") else "ANY"
                params, pann = [], []
                pl = m.child_by_field_name("parameters")
                for p in (pl.children if pl else []):
                    if p.type != "formal_parameter": continue
                    pn = txt(src, p.child_by_field_name("name")); params.append(pn)
                    for a in [c for c in p.children if c.type == "modifiers"]:
                        pann += [aname(x) for x in a.children if x.type in ("annotation", "marker_annotation")]
                name = txt(src, m.child_by_field_name("name"))
                out.append({"framework": "spring", "method": http, "path": "/".join(x for x in (base, mv) if x), "file": str(f.relative_to(root)), "function": name,
                            "params": params, "param_annotations": sorted(set(pann)), "middleware": [], "line": m.start_point[0] + 1, "end_line": m.end_point[0] + 1})
    return out

# ---------------- Servlet (@WebServlet + doGet/doPost/...) ----------------
def servlet_routes(root):
    files = [f for f in Path(root).rglob("*.java") if not skipped(f, Path(root))]; out = []
    for f in files:
        src = f.read_bytes()
        if b"WebServlet" not in src: continue
        stack = [JAVA.parse(src).root_node]
        while stack:
            n = stack.pop(); stack.extend(n.children)
            if n.type != "class_declaration": continue
            mods = [c for c in n.children if c.type == "modifiers"]
            anns = [a for m in mods for a in m.children if a.type in ("annotation", "marker_annotation")]
            ws = [a for a in anns if txt(src, a.child_by_field_name("name")) == "WebServlet"]
            if not ws: continue
            m0 = re.search(r'"([^"]*)"', txt(src, ws[0])); path = m0.group(1) if m0 else ""
            body = n.child_by_field_name("body")
            for m in (body.children if body else []):
                if m.type != "method_declaration": continue
                name = txt(src, m.child_by_field_name("name"))
                if name not in ("doGet", "doPost", "doPut", "doDelete", "service"): continue
                pl = m.child_by_field_name("parameters")
                params = [txt(src, p.child_by_field_name("name")) for p in (pl.children if pl else []) if p.type == "formal_parameter"]
                out.append({"framework": "servlet", "method": name[2:].upper() if name != "service" else "ANY", "path": path, "file": str(f.relative_to(root)), "function": name,
                            "params": params, "param_annotations": [], "middleware": [], "line": m.start_point[0] + 1, "end_line": m.end_point[0] + 1})
    return out

# ---------------- Express ----------------
VERBS = {"get", "post", "put", "delete", "patch", "all"}
def express_routes(root):
    files = [f for f in Path(root).rglob("*.js") if not skipped(f, Path(root))]
    defs = {}      # handler name -> (file, line, params) from `this.NAME = (..) =>` / `NAME = function` / `function NAME`
    for f in files:
        src = f.read_bytes(); stack = [JS.parse(src).root_node]
        while stack:
            n = stack.pop(); stack.extend(n.children)
            if n.type == "assignment_expression":
                l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
                if r is not None and r.type in ("arrow_function", "function_expression", "function") and l is not None:
                    name = txt(src, l).split(".")[-1]
                    pr = r.child_by_field_name("parameters"); ps = [txt(src, p) for p in (pr.children if pr else []) if p.type == "identifier"]
                    defs.setdefault(name, (str(f.relative_to(root)), n.start_point[0] + 1, ps))
            elif n.type == "function_declaration":
                nm = n.child_by_field_name("name"); pr = n.child_by_field_name("parameters")
                if nm is not None: defs.setdefault(txt(src, nm), (str(f.relative_to(root)), n.start_point[0] + 1, [txt(src, p) for p in (pr.children if pr else []) if p.type == "identifier"]))
    out = []
    for f in files:
        src = f.read_bytes(); stack = [JS.parse(src).root_node]
        while stack:
            n = stack.pop(); stack.extend(n.children)
            if n.type != "call_expression": continue
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or fn.type != "member_expression" or args is None: continue
            verb = txt(src, fn.child_by_field_name("property"))
            if verb not in VERBS: continue
            a = [c for c in args.children if c.type not in ("(", ")", ",")]
            if not a or a[0].type != "string": continue
            path = txt(src, a[0]).strip("'\"`")
            if not path.startswith("/"): continue
            rest = a[1:]; handler = rest[-1] if rest else None; mw = [txt(src, x) for x in rest[:-1]]
            hname = txt(src, handler).split(".")[-1] if handler is not None and handler.type in ("identifier", "member_expression") else "<inline>"
            d = defs.get(hname, (str(f.relative_to(root)), n.start_point[0] + 1, []))
            out.append({"framework": "express", "method": verb.upper(), "path": path, "file": d[0], "function": hname, "params": d[2], "param_annotations": [],
                        "middleware": mw, "line": d[1], "registered_in": str(f.relative_to(root))})
    return out

# ---------------- Flask ----------------
def _flask_body_query_fields(fn_node):
    """Walk a Flask handler's body for `request.args.get("x")` / `request.form.get("x")` (query) and
    `<anything>.get("x", ...)` off a get_json()-derived dict (body) — the field names the oracle needs
    as attack carriers but a bare decorator/url_map never declares. Heuristic: any 2+-char .get("str")
    call is a body field unless its receiver chain contains "args" or "form" (then it's a query field)."""
    query, body = set(), set()
    for n in ast.walk(fn_node):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
                and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)):
            continue
        name = n.args[0].value
        chain = ast.unparse(n.func.value) if hasattr(ast, "unparse") else ""
        if "args" in chain or "form" in chain:
            query.add(name)
        elif "headers" in chain or "cookies" in chain or "environ" in chain:
            continue                                     # not a body/query attack surface
        else:
            body.add(name)
    return sorted(query), sorted(body)


def flask_routes(root):
    out = []
    for f in Path(root).rglob("*.py"):
        if skipped(f, Path(root)): continue
        try: tree = ast.parse(f.read_text())
        except SyntaxError: continue
        for n in ast.walk(tree):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
            for d in n.decorator_list:
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ("route", "get", "post", "put", "delete", "patch") and d.args and isinstance(d.args[0], ast.Constant):
                    methods = [d.func.attr.upper()] if d.func.attr != "route" else ["GET"]
                    for kw in d.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)): methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
                    query_fields, body_fields = _flask_body_query_fields(n)
                    for m in methods:
                        out.append({"framework": "flask", "method": m, "path": d.args[0].value, "file": str(f.relative_to(root)), "function": n.name,
                                    "params": [a.arg for a in n.args.args], "param_annotations": [], "middleware": [ast.unparse(x) for x in n.decorator_list if x is not d], "line": n.lineno,
                                    "query_fields": query_fields, "body_fields": body_fields})
    return out

def main():
    root = Path(sys.argv[1]); out = Path(sys.argv[2]); spec = sys.argv[sys.argv.index("--openapi") + 1] if "--openapi" in sys.argv else None
    routes = []
    if spec: routes += openapi_routes(spec, root)
    routes += spring_routes(root) if any(root.rglob("*.java")) else []
    routes += servlet_routes(root) if any(root.rglob("*.java")) else []
    routes += express_routes(root) if (root / "package.json").exists() else []
    routes += flask_routes(root) if any(root.rglob("*.py")) else []
    json.dump({"root": str(root), "routes": routes}, open(out, "w"), indent=1)
    import collections
    print(out.name, len(routes), "routes", dict(collections.Counter(r["framework"] for r in routes)))

if __name__ == "__main__":
    main()
