"""
Applying and vetting a JavaScript patch.

Three jobs, none of which trusts the model:

  * SPLICE. The model returns the replacement for one *unit* of code (a function, with the statement
    that defines it). The unit is found by the syntax tree and replaced by byte range, so a hunk header
    that is one character off cannot fail the patch the way a textual diff does.
  * PARSE. A patch that does not parse is rejected immediately, with the position of the first error,
    which is also the feedback the model needs.
  * POLICY. The same philosophy as the C gate: a fix must be a fix. It may touch only the flagged
    function (plus new imports at the top of the file), stay small, and must not introduce the things a
    cheating patch reaches for: code execution, outbound network calls, swallowed errors, time-based
    conditions, or a function emptied out so the exploit no longer reaches anything. A dependency fix
    is vetted separately and may only change the version of an existing dependency.

Rules are generic; none names an application.
"""

import difflib
import json
import re
from dataclasses import dataclass
from typing import Optional

import tree_sitter_javascript
from tree_sitter import Language, Parser

CHANGED_LINE_CAP = 80
_FUNCTION_NODES = {"function_declaration", "generator_function_declaration", "function_expression",
                   "arrow_function", "method_definition"}
_PARSER: Optional[Parser] = None


def _parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        _PARSER = Parser(Language(tree_sitter_javascript.language()))
    return _PARSER


# -- parse check -------------------------------------------------------------------------------------

def parse_errors(source: str) -> list[str]:
    """Human-readable syntax errors ('line N: ...'), empty if the source parses cleanly."""
    src = source.encode("utf-8")
    tree = _parser().parse(src)
    errors = []
    stack = [tree.root_node]
    while stack and len(errors) < 3:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            line = n.start_point[0] + 1
            what = "missing " + n.type if n.is_missing else "unexpected: " + src[n.start_byte:n.end_byte][:40].decode("utf-8", "replace")
            errors.append(f"line {line}: {what.strip()}")
            continue
        if n.has_error:
            stack.extend(reversed(n.children))
    return sorted(errors)


# -- locating the unit to replace -----------------------------------------------------------------------

@dataclass
class Unit:
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    function_start_line: int
    function_end_line: int
    text: str


def _function_name(node, src: bytes) -> str:
    own = node.child_by_field_name("name")
    if own is not None:
        return src[own.start_byte:own.end_byte].decode()
    p = node.parent
    if p is None:
        return ""
    if p.type == "variable_declarator":
        n = p.child_by_field_name("name")
        return src[n.start_byte:n.end_byte].decode() if n is not None else ""
    if p.type == "assignment_expression":
        left = p.child_by_field_name("left")
        if left is not None and left.type == "member_expression":
            prop = left.child_by_field_name("property")
            return src[prop.start_byte:prop.end_byte].decode() if prop is not None else ""
        return src[left.start_byte:left.end_byte].decode() if left is not None else ""
    if p.type == "pair":
        k = p.child_by_field_name("key")
        return src[k.start_byte:k.end_byte].decode() if k is not None else ""
    return ""


def _unit_node(fn):
    """The node to replace: the whole defining statement for an assigned function, else the function."""
    p = fn.parent
    if p is not None and p.type == "variable_declarator" and p.parent is not None \
            and p.parent.type in ("lexical_declaration", "variable_declaration"):
        return p.parent
    if p is not None and p.type == "assignment_expression" and p.parent is not None \
            and p.parent.type == "expression_statement":
        return p.parent
    if p is not None and p.type == "pair":
        return p
    return fn


def find_unit(source: str, name: str, line: int = 0) -> Optional[Unit]:
    """
    The function called `name` (or `<anonymous@LINE>`), as a replaceable unit. If several functions
    share the name, `line` picks the one containing or starting nearest to it.
    """
    src = source.encode("utf-8")
    tree = _parser().parse(src)
    cands = []
    stack = [tree.root_node]
    anon = re.fullmatch(r"<anonymous@(\d+)>", name or "")
    while stack:
        n = stack.pop()
        if n.type in _FUNCTION_NODES:
            nm = _function_name(n, src)
            if anon:
                if not nm and n.start_point[0] + 1 == int(anon.group(1)):
                    cands.append(n)
            elif nm == name:
                cands.append(n)
        stack.extend(n.children)
    if not cands:
        return None
    if line:
        cands.sort(key=lambda n: (0 if n.start_point[0] + 1 <= line <= n.end_point[0] + 1 else 1,
                                  abs(n.start_point[0] + 1 - line)))
    fn = cands[0]
    u = _unit_node(fn)
    return Unit(u.start_byte, u.end_byte, u.start_point[0] + 1, u.end_point[0] + 1,
                fn.start_point[0] + 1, fn.end_point[0] + 1, src[u.start_byte:u.end_byte].decode("utf-8", "replace"))


def splice(source: str, unit: Unit, replacement: str) -> str:
    """Replace the unit by byte range. Trailing `;` of the replacement is kept as the model wrote it."""
    src = source.encode("utf-8")
    new = replacement.strip("\n").encode("utf-8")
    return (src[:unit.start_byte] + new + src[unit.end_byte:]).decode("utf-8", "replace")


def extract_code(response: str) -> str:
    """The model's replacement: the first fenced block (js/javascript/none), else the text itself."""
    m = re.search(r"```(?:js|javascript|node)?\s*\n(.*?)```", response, re.S)
    return (m.group(1) if m else response).strip("\n")


# -- policy -------------------------------------------------------------------------------------------------

_COMMENT_LINE = re.compile(r"^\s*(//.*|/\*.*\*/\s*|\*.*)$")

# (rule name, pattern on an ADDED line, human message). Only what a patch ADDS is judged.
_DENIED_ADDITIONS = [
    ("code_execution", re.compile(r"\b(eval|Function)\s*\(|\bnew\s+Function\b|\bvm\.\w+\("),
     "adds dynamic code execution"),
    ("shell_execution", re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\(|require\(\s*['\"]child_process['\"]\s*\)"),
     "adds shell command execution"),
    ("process_control", re.compile(r"\bprocess\.(exit|kill|abort)\s*\("), "adds process termination"),
    ("outbound_network", re.compile(r"\b(fetch|axios|needle|got)\s*[.(]|\bhttps?\.(get|request)\s*\(|\bnet\.(connect|createConnection)\s*\("),
     "adds an outbound network call"),
    ("swallowed_error", re.compile(r"catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}"), "adds an empty catch block"),
    ("time_condition", re.compile(r"\bif\s*\(.*(Date\.now\(\)|new\s+Date\()"), "adds a time-based condition"),
    ("tls_disabled", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"), "disables TLS verification"),
    ("listener", re.compile(r"\.listen\s*\("), "adds a network listener"),
]


def _code(line: str) -> str:
    """A line with string literals blanked, so text inside a string cannot trigger or hide a rule."""
    return re.sub(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)", '""', line)


def _statement_count(source: str) -> int:
    tree = _parser().parse(source.encode("utf-8"))
    n = 0
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type.endswith("_statement") or node.type in ("lexical_declaration", "variable_declaration"):
            n += 1
        stack.extend(node.children)
    return n


def check_patch(path: str, before: str, after: str, fn_start: int, fn_end: int,
                cap: int = CHANGED_LINE_CAP) -> list[str]:
    """
    Violations of the patch policy for ONE file, as readable strings (empty = allowed).
    `fn_start`/`fn_end` are the flagged function's lines in `before`.
    """
    problems: list[str] = []
    if re.search(r"(^|/)(tests?|spec|__tests__|cypress|e2e)(/|$)|\.(test|spec)\.[jt]sx?$", path):
        problems.append(f"edits a test file ({path}): a fix may not change what verifies it")
    errs = parse_errors(after)
    if errs:
        problems.append("does not parse: " + "; ".join(errs))
        return problems                                        # the rest is meaningless on broken syntax

    old, new = before.splitlines(), after.splitlines()
    ops = [op for op in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes() if op[0] != "equal"]
    changed = sum(max(i2 - i1, j2 - j1) for _, i1, i2, j1, j2 in ops)
    if changed > cap:
        problems.append(f"changes {changed} lines (cap {cap}): a fix should be minimal")

    # every change must fall inside the flagged function; new imports at the top of the file are allowed
    for tag, i1, i2, j1, j2 in ops:
        removed_inside = tag == "insert" or (i1 + 1 >= fn_start and i2 <= fn_end)
        top_imports = tag == "insert" and all(re.match(r"\s*(const|let|var|import)\b.*require\(|\s*import\b", l)
                                              for l in new[j1:j2]) and i1 < fn_start
        if tag in ("replace", "delete") and not removed_inside:
            problems.append(f"changes lines {i1 + 1}-{i2} outside the flagged function ({fn_start}-{fn_end})")
        elif tag == "insert" and not (fn_start - 1 <= i1 <= fn_end) and not top_imports:
            problems.append(f"inserts code at line {i1 + 1}, outside the flagged function ({fn_start}-{fn_end})")

    added = [l for tag, _, _, j1, j2 in ops if tag in ("insert", "replace") for l in new[j1:j2]]
    removed = [l for tag, i1, i2, _, _ in ops if tag in ("delete", "replace") for l in old[i1:i2]]
    for name, pat, msg in _DENIED_ADDITIONS:
        # Judged on the DIFF: more of it added than removed. (Swapping one dangerous call for another is
        # not a fix either, but the exploit still works then, so the proof-of-vulnerability gate fails it.)
        hits = [l for l in added if not _COMMENT_LINE.match(l) and pat.search(_code(l))]
        gone = [l for l in removed if not _COMMENT_LINE.match(l) and pat.search(_code(l))]
        if len(hits) > len(gone):
            problems.append(f"{msg}: `{hits[0].strip()[:80]}` [{name}]")

    # an emptied function: the exploit stops reaching anything, and so does every legitimate request
    before_n = _statement_count("\n".join(old[fn_start - 1:fn_end]))
    after_n = _statement_count(_function_lines_after(after, ops, fn_start, fn_end))
    if before_n >= 6 and after_n * 3 < before_n:
        problems.append(f"empties the function ({before_n} statements before, {after_n} after)")
    return problems


def _function_lines_after(after: str, ops, fn_start: int, fn_end: int) -> str:
    """
    The flagged function's text after the patch. Its new start moves by whatever was inserted above it
    (new imports), and its new end by everything changed up to and including it.
    """
    def shift(limit: int) -> int:
        return sum((j2 - j1) - (i2 - i1) for _, i1, i2, j1, j2 in ops if i2 <= limit)
    start = (fn_start - 1) + shift(fn_start - 1)
    end = fn_end + shift(fn_end)
    return "\n".join(after.splitlines()[start:end])


# -- dependency fixes --------------------------------------------------------------------------------------

def bump_dependency(package_json: str, package: str, new_version: str) -> Optional[str]:
    """
    Change the version of an EXISTING dependency, preserving the file's formatting. The new range keeps
    the caret/tilde style of the old one. Returns None if the package is not a dependency.
    """
    pat = re.compile(r'("%s"\s*:\s*")([\^~]?)([^"]+)(")' % re.escape(package))
    m = pat.search(package_json)
    if not m:
        return None
    return package_json[:m.start()] + f'{m.group(1)}{m.group(2)}{new_version}{m.group(4)}' + package_json[m.end():]


def check_dependency_patch(before: str, after: str) -> list[str]:
    """A dependency fix may change versions of existing dependencies and nothing else."""
    try:
        b, a = json.loads(before), json.loads(after)
    except ValueError as e:
        return [f"package.json does not parse: {e}"]
    problems = []
    for key in set(b) | set(a):
        if key in ("dependencies", "devDependencies"):
            continue
        if b.get(key) != a.get(key):
            problems.append(f"changes `{key}` in package.json: a dependency fix may only change versions")
    for section in ("dependencies", "devDependencies"):
        bs, as_ = b.get(section, {}) or {}, a.get(section, {}) or {}
        for name in set(as_) - set(bs):
            problems.append(f"adds a new dependency `{name}`: a fix may only change an existing version")
        for name in set(bs) - set(as_):
            problems.append(f"removes the dependency `{name}`")
    return problems
