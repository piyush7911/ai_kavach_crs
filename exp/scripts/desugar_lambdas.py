"""Deterministic lambda desugaring for taint analysis (Java). Fixes the closure-capture blind spot of the code property graph.

    python -m exp.scripts.desugar_lambdas <src-root> <dest-root>

Joern follows enhanced-for loops, sinks inside lambdas, stream map/collect and functional-interface apply, but LOSES taint that a lambda writes
into a captured variable (`list.forEach(x -> sb.append(x)); return sb.toString();`). Rewriting those statements as loops removes the closure boundary:

    X.forEach(p -> BODY);            ->  for (var p : X) BODY            (block or expression body)
    M.forEach((k, v) -> BODY);       ->  for (var _e : M.entrySet()) { var k = _e.getKey(); var v = _e.getValue(); BODY }
    O.ifPresent(p -> BODY);          ->  if (O.isPresent()) { var p = O.get(); BODY }

Only statement-level calls with exactly one lambda argument are rewritten. A bare `return;` inside the lambda body becomes `continue;` (lambda return = next element).
A second lowering handles container aliasing: `A.get(K).add(V);` also writes V through to A (`A._wt(V);`).
The rewrite is applied to a COPY (the target is never modified), and LINE COUNT IS PRESERVED: every newline of the original is kept, in the same
order, so a finding's file:line in the desugared copy is the same file:line in the original. This is a semantics-preserving lowering used only for analysis.
"""
import re, shutil, sys
from pathlib import Path
import tree_sitter_java, tree_sitter_javascript
from tree_sitter import Language, Parser

P = Parser(Language(tree_sitter_java.language()))
PJ = Parser(Language(tree_sitter_javascript.language()))
NAMES = {"forEach", "ifPresent"}

def text(src, n): return src[n.start_byte:n.end_byte]

def params_of(src, lam):
    p = lam.child_by_field_name("parameters")
    if p is None: return []
    if p.type == "identifier": return [text(src, p).decode()]
    out = []
    for c in p.children:
        if c.type == "identifier": out.append(text(src, c).decode())
        elif c.type == "formal_parameter":
            nm = c.child_by_field_name("name"); out.append(text(src, nm).decode())
    return out

def bare_returns(body, src):
    """ranges of `return;` that belong to this lambda body (not nested lambdas / classes)."""
    out, stack = [], [(body, 0)]
    while stack:
        n, depth = stack.pop()
        for c in n.children:
            if c.type in ("lambda_expression", "class_body", "anonymous_class_creation_expression"): continue
            if c.type == "return_statement" and all(x.type in ("return", ";") for x in c.children): out.append((c.start_byte, c.end_byte))
            else: stack.append((c, depth + 1))
    return out

def candidates(src):
    tree = P.parse(src); stack = [tree.root_node]; out = []
    while stack:
        n = stack.pop(); stack.extend(n.children)
        if n.type != "expression_statement" or not n.children or n.children[0].type != "method_invocation": continue
        e = n.children[0]; nm = e.child_by_field_name("name"); obj = e.child_by_field_name("object"); args = e.child_by_field_name("arguments")
        if obj is None or nm is None or args is None or text(src, nm).decode() not in NAMES: continue
        a = [c for c in args.children if c.type not in ("(", ")", ",")]
        if len(a) == 1 and a[0].type == "lambda_expression":
            ps = params_of(src, a[0])
            kind = text(src, nm).decode()
            if (kind == "forEach" and len(ps) in (1, 2)) or (kind == "ifPresent" and len(ps) == 1): out.append((n, e, obj, a[0], kind, ps))
    return out

def rewrite_one(src):
    cands = candidates(src)
    if not cands: return None
    n, e, obj, lam, kind, ps = max(cands, key=lambda c: c[0].start_byte)       # last statement first: earlier offsets stay valid
    body = lam.child_by_field_name("body"); b = src
    gap_nl = b[obj.end_byte:lam.start_byte].count(b"\n"); tail_nl = b[body.end_byte:n.end_byte].count(b"\n")
    recv = text(b, obj); recv_flat = re.sub(rb"\s*\n\s*", b" ", recv)
    btxt = bytearray(text(b, body))
    for s, en in sorted(bare_returns(body, b), reverse=True):                    # `return;` -> `continue;`
        btxt[s - body.start_byte:en - body.start_byte] = b"continue;"
    btxt = bytes(btxt); is_block = body.type == "block"
    if kind == "forEach" and len(ps) == 1:
        head = b"for (var " + ps[0].encode() + b" : " + recv + b"\n" * gap_nl + b") "
        new = head + (btxt if is_block else btxt + b";") + b"\n" * tail_nl
    elif kind == "forEach":
        decl = f" var {ps[0]} = _kv.getKey(); var {ps[1]} = _kv.getValue(); ".encode()
        head = b"for (var _kv : " + recv + b".entrySet()" + b"\n" * gap_nl + b") {" + decl
        new = head + (btxt[1:] if is_block else btxt + b"; }") + b"\n" * tail_nl
    else:  # ifPresent
        head = b"if (" + recv + b"\n" * gap_nl + b".isPresent()) { var " + ps[0].encode() + b" = " + recv_flat + b".get(); "
        new = head + (btxt[1:] if is_block else btxt + b"; }") + b"\n" * tail_nl
    return b[:n.start_byte] + new + b[n.end_byte:]

MUTATORS = {"add", "addAll", "put", "putAll", "append", "set", "push", "offer", "addFirst", "addLast"}
GETTERS = {"get", "getOrDefault", "computeIfAbsent", "getFirst", "getLast", "peek", "orElse"}

def write_through(src):
    """`A.get(K).add(V);` -> `A.get(K).add(V); A._wt(V);` on the same line. The CPG does not alias the element returned by get(), so taint added
    to it never reaches A. `_wt` is a neutral unresolved call that carries the arguments into the receiver. Newlines are untouched."""
    tree = P.parse(src); stack = [tree.root_node]; edits = []
    while stack:
        n = stack.pop(); stack.extend(n.children)
        if n.type != "expression_statement" or not n.children or n.children[0].type != "method_invocation": continue
        e = n.children[0]; nm = e.child_by_field_name("name"); obj = e.child_by_field_name("object"); args = e.child_by_field_name("arguments")
        if nm is None or obj is None or args is None or obj.type != "method_invocation" or text(src, nm).decode() not in MUTATORS: continue
        gn = obj.child_by_field_name("name"); base = obj.child_by_field_name("object")
        if gn is None or base is None or text(src, gn).decode() not in GETTERS: continue
        flat = lambda b: re.sub(rb"\s*\n\s*", b" ", b)
        a = flat(text(src, args))[1:-1]
        edits.append((n.end_byte, b" " + flat(text(src, base)) + b"._wt(" + a + b");"))
    for pos, ins in sorted(edits, reverse=True): src = src[:pos] + ins + src[pos:]
    return src, len(edits)

def desugar(src: bytes):
    count = 0
    for _ in range(300):
        r = rewrite_one(src)
        if r is None: break
        src = r; count += 1
    src, k = write_through(src)
    return src, count + k

# ---------------- JavaScript: X.forEach((x[, i]) => BODY)  ->  for (const x of X) BODY ----------------
def js_params(src, fn):
    p = fn.child_by_field_name("parameter") or fn.child_by_field_name("parameters")
    if p is None: return []
    if p.type == "identifier": return [text(src, p).decode()]
    return [text(src, c).decode() for c in p.children if c.type == "identifier"]

def js_candidates(src):
    tree = PJ.parse(src); stack = [tree.root_node]; out = []
    while stack:
        n = stack.pop(); stack.extend(n.children)
        if n.type != "expression_statement" or not n.children or n.children[0].type != "call_expression": continue
        call = n.children[0]; fn = call.child_by_field_name("function"); args = call.child_by_field_name("arguments")
        if fn is None or fn.type != "member_expression" or args is None: continue
        prop = fn.child_by_field_name("property")
        if prop is None or text(src, prop).decode() != "forEach": continue
        a = [c for c in args.children if c.type not in ("(", ")", ",")]
        if len(a) == 1 and a[0].type in ("arrow_function", "function_expression", "function"):
            ps = js_params(src, a[0])
            if len(ps) <= 2: out.append((n, fn, a[0], ps))
    return out

def js_rewrite_one(src):
    cands = js_candidates(src)
    if not cands: return None
    n, fn, lam, ps = max(cands, key=lambda c: c[0].start_byte)
    obj = fn.child_by_field_name("object"); body = lam.child_by_field_name("body")
    gap_nl = src[obj.end_byte:lam.start_byte].count(b"\n"); tail_nl = src[body.end_byte:n.end_byte].count(b"\n")
    recv = text(src, obj); btxt = bytearray(text(src, body)); stack = [body]
    while stack:                                                   # bare `return;` in the callback -> continue
        x = stack.pop()
        for c in x.children:
            if c.type in ("arrow_function", "function_expression", "function", "function_declaration", "class_body"): continue
            if c.type == "return_statement" and all(y.type in ("return", ";") for y in c.children):
                btxt[c.start_byte - body.start_byte:c.end_byte - body.start_byte] = b"continue;"
            else: stack.append(c)
    btxt = bytes(btxt); is_block = body.type == "statement_block"
    if len(ps) == 2: head = b"for (const [" + ps[1].encode() + b", " + ps[0].encode() + b"] of " + recv + b".entries()" + b"\n" * gap_nl + b") "
    else: head = b"for (const " + (ps[0] if ps else "_kv").encode() + b" of " + recv + b"\n" * gap_nl + b") "
    new = head + (btxt if is_block else btxt + b";") + b"\n" * tail_nl
    return src[:n.start_byte] + new + src[n.end_byte:]

def desugar_js(src: bytes):
    count = 0
    for _ in range(300):
        r = js_rewrite_one(src)
        if r is None: break
        src = r; count += 1
    return src, count

def main():
    root, dest = Path(sys.argv[1]), Path(sys.argv[2]); total = files = 0
    for f in [x for x in root.rglob("*") if x.suffix in (".java", ".js") and "node_modules" not in x.parts]:
        out = dest / f.relative_to(root); out.parent.mkdir(parents=True, exist_ok=True)
        s = f.read_bytes(); new, k = desugar(s) if f.suffix == ".java" else desugar_js(s)
        assert s.count(b"\n") == new.count(b"\n"), f"line count changed in {f}"
        out.write_bytes(new); total += k; files += (k > 0)
    print(f"{dest}: {total} callback/lambda statements rewritten in {files} files; line counts preserved")

if __name__ == "__main__":
    main()
