"""Mine sources / sinks / sanitizers out of community Semgrep *taint-mode* rules into per-language DATA files.

    python -m exp.scripts.mine_taint_rules            # writes exp/knowledge/{python,java,javascript}.json

Each Semgrep taint rule already says: pattern-sources (where attacker data enters), pattern-sinks (dangerous calls) and
pattern-sanitizers (calls that neutralise it). We turn each *call-shaped* pattern into a small spec
  {"name": "execute", "recv": "cursor|\\w+", "type": "HttpServletRequest"|null, "arg": 0|null, "fw": "flask", "rule": "<id>"}
and group by vulnerability class (from the rule's CWE). Patterns we cannot express as a call spec are counted, not hidden.
Nothing here looks at any benchmark: the input is the generic rules only.
"""
import collections, json, re, sys
from pathlib import Path
from ruamel.yaml import YAML
_Y = YAML(typ="safe")

SR = Path("exp/third_party/semgrep-rules")
OUT = Path("exp/knowledge")
LANGS = {"python": ["python"], "java": ["java"], "javascript": ["javascript", "typescript"]}
CWE = {89: "sql-injection", 564: "sql-injection", 943: "nosql-injection", 78: "command-injection", 77: "command-injection", 88: "command-injection",
       94: "code-injection", 95: "code-injection", 96: "code-injection", 917: "code-injection", 22: "path-traversal", 23: "path-traversal", 36: "path-traversal",
       918: "ssrf", 79: "xss", 80: "xss", 83: "xss", 611: "xxe", 776: "xxe", 827: "xxe", 502: "deserialization", 601: "open-redirect", 1336: "ssti",
       90: "ldap-injection", 643: "xpath-injection", 113: "header-injection", 134: "format-string", 98: "file-inclusion", 73: "path-traversal",
       74: "injection-other", 20: "input-validation", 470: "unsafe-reflection", 117: "log-injection", 1333: "redos", 400: "redos", 1236: "csv-injection"}
ID_HINTS = [("sql", "sql-injection"), ("nosql", "nosql-injection"), ("command", "command-injection"), ("exec", "command-injection"), ("subprocess", "command-injection"),
            ("eval", "code-injection"), ("xss", "xss"), ("ssrf", "ssrf"), ("redirect", "open-redirect"), ("xxe", "xxe"), ("ssti", "ssti"), ("template", "ssti"),
            ("path", "path-traversal"), ("traversal", "path-traversal"), ("deserial", "deserialization"), ("pickle", "deserialization"), ("ldap", "ldap-injection"),
            ("xpath", "xpath-injection"), ("tainted-url", "ssrf")]

def classify(rule):
    cw = rule.get("metadata", {}).get("cwe", [])
    cw = cw if isinstance(cw, list) else [cw]
    for c in cw:
        for n in re.findall(r"CWE-(\d+)", str(c)):
            if int(n) in CWE: return CWE[int(n)]
    rid = rule.get("id", "").lower()
    for k, v in ID_HINTS:
        if k in rid: return v
    return "other"

MV = re.compile(r"\$[A-Z_][A-Z0-9_]*")
def rx(seg):                      # one dotted segment -> regex; metavariables match any identifier
    seg = seg.strip()
    if seg in ("...", ""): return r"[\w$]+"
    return re.sub(r"\\\$[A-Z_][A-Z0-9_]*", r"[\\w$]+", re.escape(seg)).replace(r"\.\.\.", ".*")

def leaf_spec(p, fw, rule_id, focus=None, mvrx=None):
    """pattern string -> spec dict, or None if it is not call/access shaped."""
    p = p.strip()
    if "\n" in p:                  # multi-line (function / decorator patterns)
        return param_spec(p, fw, rule_id, focus, mvrx)
    mt = re.fullmatch(r"\(\s*([\w.<>\[\]]+)\s+\$\w+\s*\)", p)                 # typed value: (HttpServletRequest $REQ)
    if mt: return {"kind": "typed", "type": mt.group(1).split("<")[0].split(".")[-1], "fw": fw, "rule": rule_id}
    p = re.sub(r"^(await|return|yield|throw|new)\s+", lambda m: "new " if m.group(1) == "new" else "", p)
    jtype = None
    m = re.match(r"^\(\s*([\w.<>\[\]?, ]+?)\s+\$\w+\s*\)\s*\.", p)         # Java cast receiver: (HttpServletRequest $R).getX(...)
    if m: jtype = m.group(1).split("<")[0].split(".")[-1]; p = "$_RCV." + p[m.end():]
    m = re.match(r"^(new\s+)?([\w$.\[\]\"'\s()-]*?)\s*\((.*)\)\s*(\.\w+\(.*\))?$", p, re.S)   # callee(args)
    kind = "call"
    if not m:
        m2 = re.match(r"^([\w$.]+)(\[.*\])?$", p)                           # plain access: flask.request.args / request.args[...]
        if not m2: return None
        callee, args, ctor, kind = m2.group(1), "", False, "access"
    else:
        ctor, callee, args = bool(m.group(1)), m.group(2).strip(), m.group(3)
    callee = re.sub(r"\(.*?\)", "", callee)                                 # drop call chains like getRuntime()
    segs = [s for s in callee.split(".") if s != ""]
    if not segs: return None
    if len(segs) >= 4 or (len(segs) == 3 and segs[0][0].islower() and segs[0] in ("flask", "django", "http", "express")): segs = segs[1:]
    name = "<init>" if ctor else segs[-1]
    if not ctor and MV.fullmatch(name): name = ".*"
    recv = ".".join(rx(s) for s in segs[:-1]) if len(segs) > 1 and not ctor else None
    if ctor: name_rx = re.escape(segs[-1]) if not MV.fullmatch(segs[-1]) else ".*"
    else: name_rx = ".*" if name == ".*" else re.escape(name)
    arg = None
    if focus and args:
        parts = [a.strip() for a in re.split(r",(?![^()]*\))", args)]
        for i, a in enumerate(parts):
            if focus in a: arg = i; break
    return {"kind": kind, "name": name_rx if not ctor else re.escape(segs[-1]) if not MV.fullmatch(segs[-1]) else ".*",
            "ctor": ctor, "recv": recv, "type": jtype, "arg": arg, "fw": fw, "rule": rule_id}

ANN = re.compile(r"@([\w.]+)")
def param_spec(p, fw, rule_id, focus, mvrx=None):
    """decorated / annotated handler whose parameter is the source, e.g. @app.route(...) def f(..., $X) or Spring @RequestParam."""
    anns = [a.split(".")[-1] for a in ANN.findall(p)]
    for var in re.findall(r"@(\$[A-Z_][A-Z0-9_]*)\b(?!\.)", p):                         # @$REQ(...) + metavariable-regex
        rxs = (mvrx or {}).get(var)
        if rxs: anns += [w for w in re.findall(r"[A-Za-z_]\w+", rxs) if w not in ("i", "s")]
    anns += re.findall(r"@\$[A-Z_][A-Z0-9_]*\.(\w+)", p)                                 # @$APP.route(...)
    anns = [a for a in anns if not MV.fullmatch("$" + a)]
    if not anns: return None
    return {"kind": "param", "annotations": sorted(set(anns)), "fw": fw, "rule": rule_id}

def walk(node, fw, rid, stats, focus=None, mvrx=None):
    """positive leaf patterns under a pattern tree (skip pattern-not / pattern-inside etc.)."""
    out = []
    if isinstance(node, list):
        mv = dict(mvrx or {})
        for x in node:
            if isinstance(x, dict) and isinstance(x.get("metavariable-regex"), dict):
                mv[x["metavariable-regex"].get("metavariable")] = x["metavariable-regex"].get("regex", "")
        for x in node: out += walk(x, fw, rid, stats, focus, mv)
    elif isinstance(node, dict):
        f = node.get("focus-metavariable", focus)
        if "pattern" in node:
            s = leaf_spec(str(node["pattern"]), fw, rid, f if isinstance(f, str) else None, mvrx)
            stats["parsed" if s else "skipped"] += 1
            if s: out.append(s)
        if "pattern-regex" in node: stats["skipped"] += 1
        for k in ("patterns", "pattern-either"):
            if k in node: out += walk(node[k], fw, rid, stats, f if isinstance(f, str) else None, mvrx)
        if "pattern-inside" in node:
            s = leaf_spec(str(node["pattern-inside"]), fw, rid, f if isinstance(f, str) else None, mvrx)
            if s and s["kind"] == "param": out.append(s); stats["parsed"] += 1
    return out

def too_generic(s):
    if s["kind"] in ("param", "typed"): return False
    meta = r"[\w$]+"
    recv_empty = s.get("recv") in (None, "", meta) or all(seg == meta for seg in (s.get("recv") or "").split("."))
    return s["name"] in (".*", meta) and recv_empty

def dedupe(specs):
    seen, out = set(), []
    for s in specs:
        if too_generic(s): continue
        k = json.dumps({a: b for a, b in s.items() if a not in ("rule", "fw")}, sort_keys=True)
        if k in seen: continue
        seen.add(k); out.append(s)
    return out

def mine(lang):
    sources, sinks, sans = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
    stats = collections.Counter(); nrules = 0; fwcount = collections.Counter()
    for sub in LANGS[lang]:
        for f in sorted((SR / sub).rglob("*.y*ml")):
            if f.name.endswith(".test.yaml") or f.name.endswith(".fixed.yaml"): continue
            try: doc = _Y.load(f.read_text())
            except Exception: stats["yaml-error"] += 1; continue
            for r in (doc or {}).get("rules", []) or []:
                if r.get("mode") != "taint": continue
                nrules += 1
                parts = f.relative_to(SR).parts; fw = parts[1] if len(parts) > 2 else parts[0]; fwcount[fw] += 1
                cls = classify(r)
                sources[cls] += walk(r.get("pattern-sources", []), fw, r["id"], stats)
                sinks[cls] += walk(r.get("pattern-sinks", []), fw, r["id"], stats)
                sans[cls] += walk(r.get("pattern-sanitizers", []), fw, r["id"], stats)
    data = {"_about": f"Mined from semgrep-rules taint-mode rules ({lang}); generic ecosystem knowledge, no benchmark input. Each spec keeps fw/rule provenance.",
            "taint_rules": nrules, "patterns_parsed": stats["parsed"], "patterns_skipped": stats["skipped"], "frameworks": dict(fwcount.most_common()),
            "sources": {c: dedupe(v) for c, v in sources.items()}, "sinks": {c: dedupe(v) for c, v in sinks.items()}, "sanitizers": {c: dedupe(v) for c, v in sans.items()}}
    return data

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for lang in LANGS:
        d = mine(lang); json.dump(d, open(OUT / f"{lang}.json", "w"), indent=1)
        print(f"{lang}: {d['taint_rules']} taint rules | patterns parsed {d['patterns_parsed']} / skipped {d['patterns_skipped']} | "
              f"sources " + ", ".join(f"{c}:{len(v)}" for c, v in sorted(d['sources'].items(), key=lambda x: -len(x[1]))[:8]) + " | sinks " + ", ".join(f"{c}:{len(v)}" for c, v in sorted(d['sinks'].items(), key=lambda x: -len(x[1]))[:10]))
        print("   frameworks:", dict(list(d["frameworks"].items())[:8]))
