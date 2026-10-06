"""Deterministic wire-parameter extraction from source — no LLM.

A static/Joern/Opengrep candidate names a (file, function) and a class; the oracle needs the HTTP parameter
the handler actually reads. This resolves it from the source, language-agnostically:
  - Java: @RequestParam("x") / @RequestParam(CONST), queryParams.get(CONST|"x"), request.getParameter(...)
  - Python: request.args/form/values/json.get("x") / [...], flask request.*
String CONSTANTS are resolved against the whole tree (VulnerableApp reads queryParams.get(Constants.ID),
and `String ID = "id"` elsewhere), the way the LLM would read the code — but exact, offline, and fast.

Keyed by file basename (params are per file; a vuln controller is one class). Returns a lookup used by the
route-map confirm bridge. This is what lets the Joern->route->param->oracle path run with no model.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

_CONST = re.compile(r'(?:final\s+)?(?:String|var)\s+(\w+)\s*=\s*"([^"]*)"')      # Java/TS string constants
# any `recv.get(ARG)` / `recv.getParameter(ARG)`; resolve() only yields a param when ARG is a string
# literal or a known string constant, so list.get(0) / validator.get() contribute nothing (self-filtering).
_JAVA_GET = re.compile(r'\b\w+\.get(?:Parameter)?\(\s*([^),]+?)\s*\)')
_JAVA_RP_LIT = re.compile(r'@RequestParam\(\s*(?:value\s*=\s*)?"([^"]+)"')
_JAVA_RP_CONST = re.compile(r'@RequestParam\(\s*(?:value\s*=\s*)?([A-Za-z_]\w*(?:\.\w+)?)\s*\)')
_PY_GET = re.compile(r'request\.(?:args|form|values|json|GET|POST)(?:\.get)?\(\s*[\'"]([^\'"]+)[\'"]')
_PY_IDX = re.compile(r'request\.(?:args|form|values|json|GET|POST)\[\s*[\'"]([^\'"]+)[\'"]\s*\]')
_EXTS = (".java", ".py", ".js", ".ts", ".kt")
_SKIP = ("node_modules", "/test/", "/tests/", "/build/", "/.git/", "/target/")


def build_param_lookup(root: str | Path):
    """Scan the source tree once; return lookup(file_basename) -> sorted list of wire param names."""
    root = Path(root)
    consts: dict[str, str] = {}
    texts: dict[str, str] = {}
    for f in root.rglob("*"):
        if f.suffix not in _EXTS or any(s in "/" + str(f).replace("\\", "/") for s in _SKIP):
            continue
        try:
            t = f.read_text(errors="replace")
        except OSError:
            continue
        texts.setdefault(f.name, "")
        texts[f.name] += "\n" + t                       # same basename in two dirs: union their text
        for m in _CONST.finditer(t):
            consts.setdefault(m.group(1), m.group(2))

    def resolve(arg: str):
        arg = arg.strip()
        if len(arg) >= 2 and arg[0] in "\"'" and arg[-1] in "\"'":
            return arg[1:-1]
        return consts.get(arg.split(".")[-1])           # Constants.ID -> ID -> "id"

    params: dict[str, set] = defaultdict(set)
    for name, t in texts.items():
        for m in _JAVA_GET.finditer(t):
            v = resolve(m.group(1))
            if v:
                params[name].add(v)
        for m in _JAVA_RP_LIT.finditer(t):
            params[name].add(m.group(1))
        for m in _JAVA_RP_CONST.finditer(t):
            v = resolve(m.group(1))
            if v:
                params[name].add(v)
        for rx in (_PY_GET, _PY_IDX):
            for m in rx.finditer(t):
                params[name].add(m.group(1))

    return lambda basename: sorted(params.get(basename, set()))
