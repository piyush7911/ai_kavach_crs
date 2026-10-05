"""
Autonomous mode — fuzz-harness synthesis for a flagged function.

The pipeline already knows *which* function is suspect (a static finding or a
crash frame). This module builds a libFuzzer harness that reaches it through
an honest call path, in this order:

  1. **Entry point.** If the flagged function is callable from outside its file
     it is the entry point. If it is `static`, its callers are walked upward
     (breadth-first, a few levels) to the nearest externally visible caller.
  2. **Preconditions from real callers.** Every call site of the entry point is
     read: arguments that are always integer literals become a closed set the
     harness picks from; arguments that are local arrays of literal size fix
     the buffer size the harness allocates; `sizeof(x)` ties a length to a
     buffer. The harness never hands the function an argument no real caller
     could hand it.
  3. **Template first.** Parameter shapes the templates understand —
     byte buffer + length, C string, integers, caller-sized output buffers —
     are filled deterministically, with no model call.
  4. **Model second.** Shapes the templates cannot express (struct pointers,
     callbacks, ...) are drafted by the LLM, then judged by the compiler, the
     fairness check below and, later, the reach judge. The model's text is
     never trusted on its own.

Fairness (checked for every harness, template or drafted):
  * input buffers are allocated at exactly the size the harness claims;
  * a parameter whose callers only ever pass literals receives one of those
    literals;
  * a buffer argument is never smaller than the smallest a real caller passes;
  * the harness calls the entry point (a harness that never does is rejected).

"Reaches the flagged function" is decided by running it (see runner.py), not
by reading it.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.autonomy.codeindex import CallSite, CodeIndex, Function, Param

BYTE_TYPES = {"char", "signed char", "unsigned char", "uint8_t", "int8_t", "u8", "u_char",
              "Bytef", "Byte", "byte", "uchar", "guchar", "gchar", "void", "png_byte",
              "png_bytep", "xmlChar", "JSOCTET", "UChar", "UINT8"}
INT_TYPES = {"int", "unsigned", "unsigned int", "signed", "signed int", "long", "unsigned long",
             "long long", "unsigned long long", "short", "unsigned short", "size_t", "ssize_t",
             "off_t", "uint32_t", "int32_t", "uint16_t", "int16_t", "uint64_t", "int64_t",
             "uInt", "uLong", "uLongf", "z_size_t", "intptr_t", "uintptr_t", "char",
             "unsigned char", "uint8_t", "int8_t", "bool", "_Bool", "u32", "u16", "u64",
             "size32_t", "DWORD", "UINT", "ULONG"}
LEN_NAMES = re.compile(r"^(len|length|size|sz|n|count|cnt|nbytes|bytes|num|buflen|bufsize|"
                       r"\w*_?(len|length|size|sz|count|bytes))$", re.IGNORECASE)
OUT_NAMES = re.compile(r"^(out|dst|dest|output|outbuf|buf|buffer|result|res|o|target)\w*$",
                       re.IGNORECASE)
MAX_INPUT = 4096


class HarnessUnavailable(RuntimeError):
    """No fair harness can be built for this function. The message is the reason."""


@dataclass
class Preconditions:
    """What real callers of a function guarantee about its arguments."""
    literals: dict[int, list[str]] = field(default_factory=dict)   # param index -> literal set
    buffer_size: dict[int, int] = field(default_factory=dict)       # param index -> min caller size
    sizeof_of: dict[int, int] = field(default_factory=dict)         # len index -> buffer index
    call_sites: int = 0

    def describe(self) -> list[str]:
        out = [f"{self.call_sites} call site(s) read"]
        for i, vals in sorted(self.literals.items()):
            out.append(f"param {i}: callers pass only literals {{{', '.join(vals)}}}")
        for i, n in sorted(self.buffer_size.items()):
            out.append(f"param {i}: callers pass a buffer of at least {n} bytes")
        for i, j in sorted(self.sizeof_of.items()):
            out.append(f"param {i}: callers pass sizeof(param {j})")
        return out


@dataclass
class Harness:
    entry: Function            # the function the harness calls
    target: Function           # the flagged function it must reach
    source: str
    method: str                # "template" | "llm" | "existing"
    path: Optional[Path] = None
    preconditions: Optional[Preconditions] = None
    notes: list[str] = field(default_factory=list)
    seeds: list[bytes] = field(default_factory=list)
    call_path: list[str] = field(default_factory=list)


# -- preconditions -----------------------------------------------------------------

def _is_int_literal(text: str) -> bool:
    return bool(re.fullmatch(r"-?(0[xX][0-9a-fA-F]+|\d+)[uUlL]*", text.strip()))


def mine_preconditions(index: CodeIndex, fn: Function) -> Preconditions:
    pre = Preconditions()
    sites = [s for s in index.callers_of(fn.name) if len(s.args) == len(fn.params)]
    pre.call_sites = len(sites)
    if not sites:
        return pre
    for i, param in enumerate(fn.params):
        args = [s.args[i] for s in sites]
        if all(_is_int_literal(a) or a in index.macros for a in args):
            values = []
            for a in args:
                v = a if _is_int_literal(a) else str(index.macros[a])
                if v not in values:
                    values.append(v)
            pre.literals[i] = values
        sizes = []
        for s in sites:
            a = s.args[i].lstrip("&").strip()
            if a in s.arrays:
                sizes.append(s.arrays[a])
        if sizes and len(sizes) == len(sites):
            pre.buffer_size[i] = min(sizes)
        for s in sites:
            m = re.fullmatch(r"sizeof\s*\(?\s*([A-Za-z_]\w*)\s*\)?", s.args[i])
            if m:
                for j, other in enumerate(s.args):
                    if j != i and other.lstrip("&").strip() == m.group(1):
                        pre.sizeof_of[i] = j
    return pre


# -- entry-point selection ------------------------------------------------------------

def call_path_to(index: CodeIndex, target: Function, max_depth: int = 3) -> list[list[Function]]:
    """Paths [entry, ..., target] where entry is externally callable. Shortest first."""
    if not target.is_static:
        return [[target]]
    frontier = [[target]]
    found = []
    seen = {target.name}
    for _ in range(max_depth):
        nxt = []
        for path in frontier:
            for site in index.callers_of(path[0].name):
                caller = index.function(site.caller, site.file) or index.function(site.caller)
                if caller is None or caller.name in seen:
                    continue
                seen.add(caller.name)
                new = [caller] + path
                (found if not caller.is_static else nxt).append(new)
        if found:
            return found
        frontier = nxt
    return found


# -- templates ---------------------------------------------------------------------------

@dataclass
class _Slot:
    kind: str          # "buf" | "len" | "cstr" | "int" | "lit" | "outbuf"
    param: Param
    partner: int = -1  # buf<->len pairing
    size: int = 0      # fixed size for outbuf
    literals: list[str] = field(default_factory=list)


def _byte_pointer(p: Param) -> bool:
    return p.pointer_depth == 1 and p.base in BYTE_TYPES


def _integer(p: Param) -> bool:
    return p.pointer_depth == 0 and p.base in INT_TYPES


def plan_slots(fn: Function, pre: Preconditions) -> Optional[list[_Slot]]:
    """Map each parameter to a template slot, or None if a shape is not expressible."""
    params = fn.params
    if fn.variadic:
        return None
    slots: list[Optional[_Slot]] = [None] * len(params)

    # 1. buffer + length pairs first: a length that travels with a buffer must
    #    equal that buffer's real size, whatever literal a caller happened to
    #    pass. Explicit sizeof() relation first, then adjacency/name.
    for li, bi in pre.sizeof_of.items():
        if slots[li] is None and slots[bi] is None and _byte_pointer(params[bi]) and _integer(params[li]):
            size = pre.buffer_size.get(bi, 0)
            if size:
                slots[bi] = _Slot("outbuf", params[bi], partner=li, size=size)
                slots[li] = _Slot("len", params[li], partner=bi, size=size)
            else:
                slots[bi] = _Slot("buf", params[bi], partner=li)
                slots[li] = _Slot("len", params[li], partner=bi)
    for i, p in enumerate(params):
        if slots[i] is not None or not _byte_pointer(p):
            continue
        j = i + 1
        if j < len(params) and slots[j] is None and _integer(params[j]) and (
                LEN_NAMES.match(params[j].name or "")
                or (len(params) == 2 and j not in pre.literals)):
            if i in pre.buffer_size and OUT_NAMES.match(p.name or "") and "const" not in p.type:
                slots[i] = _Slot("outbuf", p, partner=j, size=pre.buffer_size[i])
                slots[j] = _Slot("len", params[j], partner=i, size=pre.buffer_size[i])
            else:
                slots[i] = _Slot("buf", p, partner=j)
                slots[j] = _Slot("len", params[j], partner=i)

    # 2. literal-only parameters (from callers) that are not lengths
    for i, vals in pre.literals.items():
        if slots[i] is None and _integer(params[i]):
            slots[i] = _Slot("lit", params[i], literals=vals)

    # 3. remaining byte pointers: caller-sized output buffer, else C string
    for i, p in enumerate(params):
        if slots[i] is not None or not _byte_pointer(p):
            continue
        if i in pre.buffer_size and "const" not in p.type:
            slots[i] = _Slot("outbuf", p, size=pre.buffer_size[i])
        elif p.base != "void":
            slots[i] = _Slot("cstr", p)
        else:
            return None                      # void* with no length: not expressible

    # 4. remaining integers
    for i, p in enumerate(params):
        if slots[i] is None and _integer(p):
            slots[i] = _Slot("int", p)

    if any(s is None for s in slots):
        return None
    # At most one consumer of "the rest of the input" keeps the split honest.
    if sum(1 for s in slots if s.kind in ("buf", "cstr")) > 2:
        return None
    return slots  # type: ignore[return-value]


def _prototype(fn: Function) -> str:
    sig = re.sub(r"\b(static|inline|__inline|__inline__|extern)\b", " ", fn.signature)
    sig = re.sub(r"__attribute__\s*\(\(.*?\)\)", " ", sig)
    return " ".join(sig.split()) + ";"


_INT_RETURN = re.compile(
    r"^(?:(?:unsigned|signed|short|long|int|char|size_t|ssize_t|bool|_Bool|u?int(?:8|16|32|64)_t"
    r"|ptrdiff_t|off_t|intptr_t|uintptr_t)\s*)+$")


def _integer_return(return_type: str) -> bool:
    """True when a function returns a plain integer we can print. Pointers, structs and void are not traced."""
    t = re.sub(r"\b(static|inline|extern|const|volatile|__inline|__inline__)\b", " ", return_type or "")
    t = " ".join(t.split())
    return bool(t) and "*" not in t and bool(_INT_RETURN.match(t))


def render_template(entry: Function, slots: list[_Slot], include: Optional[str]) -> str:
    lines = [
        "/* Generated by AI Kavach autonomous mode (template harness). */",
        "#include <stdint.h>", "#include <stddef.h>", "#include <stdlib.h>",
        "#include <string.h>", "#include <stdio.h>",
    ]
    if include:
        lines.append(f'#include "{Path(include).name}"')
    else:
        lines.append(_prototype(entry))
    lines += [
        "",
        "static __attribute__((unused)) uint64_t kv_take(const uint8_t **d, size_t *n, size_t k) {",
        "    uint64_t v = 0;",
        "    for (size_t i = 0; i < k && *n > 0; i++) { v = (v << 8) | **d; (*d)++; (*n)--; }",
        "    return v;",
        "}",
        "",
        "/* Behaviour trace. Silent while fuzzing; set KAVACH_TRACE=1 when REPLAYING an",
        "   input and the harness prints what the call returned and what it wrote, so a",
        "   patched build can be compared with the original on the same input. */",
        "static __attribute__((unused)) int kv_tracing(void) { return getenv(\"KAVACH_TRACE\") != NULL; }",
        "static __attribute__((unused)) void kv_trace_ret(long long v) { if (kv_tracing()) printf(\"ret=%lld\\n\", v); }",
        "static __attribute__((unused)) void kv_trace_bytes(const char *label, const uint8_t *p, size_t n) {",
        "    if (!kv_tracing()) return;",
        "    printf(\"%s=\", label);",
        "    for (size_t i = 0; i < n && i < 64; i++) printf(\"%02x\", p[i]);",
        "    printf(\"\\n\");",
        "}",
        "",
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
        f"    if (size > {MAX_INPUT}) return 0;",
    ]
    decls, frees, args = [], [], []
    consumers = [i for i, s in enumerate(slots) if s.kind in ("buf", "cstr")]
    # Fixed-width reads first, so the variable-length tail is what remains.
    for i, s in enumerate(slots):
        v = f"a{i}"
        ctype = s.param.type or "int"
        if s.kind == "lit":
            vals = ", ".join(s.literals)
            decls.append(f"    static const long long lits{i}[] = {{{vals}}};")
            decls.append(f"    {ctype} {v} = ({ctype})lits{i}[kv_take(&data, &size, 1) % "
                         f"{len(s.literals)}];")
        elif s.kind == "int":
            width = 1 if s.param.base in ("char", "unsigned char", "uint8_t", "int8_t",
                                           "bool", "_Bool") else 4
            decls.append(f"    {ctype} {v} = ({ctype})kv_take(&data, &size, {width});")
        elif s.kind == "outbuf":
            decls.append(f"    uint8_t *{v} = (uint8_t *)malloc({s.size});")
            decls.append(f"    if (!{v}) return 0;")
            decls.append(f"    memset({v}, 0, {s.size});")
            frees.append(f"    free({v});")
    split = ""
    if len(consumers) == 2:
        # One byte decides where the input splits between the two buffers.
        split = "    size_t cut = size ? (size_t)kv_take(&data, &size, 1) % (size + 1) : 0;\n"
    if split:
        decls.append(split.rstrip("\n"))
    for n, i in enumerate(consumers):
        s = slots[i]
        v = f"a{i}"
        if len(consumers) == 2:
            start, length = ("0", "cut") if n == 0 else ("cut", "size - cut")
        else:
            start, length = "0", "size"
        if s.kind == "buf":
            # Exactly `length` bytes, so a read one past the end is an ASan report.
            decls.append(f"    size_t n{i} = {length};")
            decls.append(f"    uint8_t *{v} = (uint8_t *)malloc(n{i} ? n{i} : 1);")
            decls.append(f"    if (!{v}) return 0;")
            decls.append(f"    if (n{i}) memcpy({v}, data + {start}, n{i});")
        else:
            decls.append(f"    size_t n{i} = {length};")
            decls.append(f"    char *{v} = (char *)malloc(n{i} + 1);")
            decls.append(f"    if (!{v}) return 0;")
            decls.append(f"    if (n{i}) memcpy({v}, data + {start}, n{i});")
            decls.append(f"    {v}[n{i}] = '\\0';")
        frees.append(f"    free({v});")
    for i, s in enumerate(slots):
        if s.kind == "len":
            partner = slots[s.partner]
            if partner.kind == "outbuf":
                decls.append(f"    {s.param.type or 'size_t'} a{i} = ({s.param.type or 'size_t'}){partner.size};")
            else:
                decls.append(f"    {s.param.type or 'size_t'} a{i} = ({s.param.type or 'size_t'})n{s.partner};")
    for i, s in enumerate(slots):
        cast = f"({s.param.type})" if s.kind in ("buf", "cstr", "outbuf") and s.param.type else ""
        args.append(f"{cast}a{i}")
    lines += decls
    call = f"{entry.name}({', '.join(args)})"
    if _integer_return(entry.return_type):
        lines.append(f"    kv_trace_ret((long long){call});")
    else:
        lines.append(f"    (void){call};")
    for i, s_ in enumerate(slots):
        if s_.kind == "outbuf":
            lines.append(f'    kv_trace_bytes("out{i}", a{i}, {s_.size});')
    lines += frees
    lines += ["    return 0;", "}", ""]
    return "\n".join(lines)


def seeds_for(slots: list[_Slot]) -> list[bytes]:
    """A few structurally valid starting inputs; the repo's own test data is added by the runner."""
    if any(s.kind == "cstr" for s in slots):
        return [b"a", b"hello world", b"0123456789" * 8]
    return [b"\x00", b"\x01" * 16, bytes(range(64))]


# -- fairness ------------------------------------------------------------------------------

def fairness_violations(source: str, entry: Function, pre: Preconditions) -> list[str]:
    """Static checks that a harness honours what real callers guarantee."""
    problems = []
    calls = list(re.finditer(r"\b" + re.escape(entry.name) + r"\s*\(", source))
    if not calls:
        return [f"harness never calls {entry.name}()"]
    if "LLVMFuzzerTestOneInput" not in source:
        problems.append("harness has no LLVMFuzzerTestOneInput entry point")

    # Arguments of each call, split at top-level commas.
    for m in calls:
        i, depth, cur, args = m.end(), 1, "", []
        while i < len(source) and depth:
            ch = source[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            if ch == "," and depth == 1:
                args.append(cur.strip())
                cur = ""
            else:
                cur += ch
            i += 1
        args.append(cur.strip())
        if len(args) != len(entry.params):
            continue                                        # a prototype, not a call
        for idx, vals in pre.literals.items():
            a = re.sub(r"^\([^()]*\)\s*", "", args[idx])   # drop a cast
            if _is_int_literal(a) and a.rstrip("uUlL") not in [v.rstrip("uUlL") for v in vals]:
                problems.append(f"passes {a} as parameter {idx}; callers only pass "
                                f"{{{', '.join(vals)}}}")
        for idx, need in pre.buffer_size.items():
            name = re.sub(r"^\([^()]*\)\s*", "", args[idx]).lstrip("&").strip()
            for decl in (re.search(r"\b" + re.escape(name) + r"\s*\[\s*(\d+)\s*\]", source),
                         re.search(r"\b" + re.escape(name) + r"\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)",
                                   source)):
                if decl and int(decl.group(1)) < need:
                    problems.append(f"passes a {decl.group(1)}-byte buffer as parameter {idx}; "
                                    f"the smallest real caller passes {need}")
    # Buffers built from the input must not be allocated short of what is copied in.
    for m in re.finditer(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*([^;]+?)\s*\)\s*;", source):
        var, size_expr = m.group(1), m.group(2)
        copy = re.search(r"memcpy\s*\(\s*" + re.escape(var) + r"\s*,[^,]+,\s*([^;]+?)\s*\)\s*;", source)
        if copy and re.fullmatch(r"\d+", size_expr) and re.fullmatch(r"\d+", copy.group(1)):
            if int(copy.group(1)) > int(size_expr):
                problems.append(f"copies {copy.group(1)} bytes into {var}, allocated {size_expr}")
    return problems


# -- synthesis ------------------------------------------------------------------------------

LLM_SYSTEM = (
    "You write libFuzzer harnesses in C for security testing. Output exactly one ```c code "
    "block and nothing else. The harness must define "
    "`int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and call the ENTRY "
    "function with arguments derived from `data`. Rules: allocate every buffer you pass at "
    "exactly the size you claim for it (malloc the size, then copy); never pass NULL where "
    "the callers shown never do; when callers only pass certain literal values for an "
    "argument, use only those values; do not add early returns other than rejecting "
    "inputs that are too large; do not define main(); do not re-implement the entry function; "
    "free what you allocate. The fuzzer's `data` is raw bytes and is NOT NUL-terminated: for "
    "any `char *` string argument, malloc size+1, memcpy the bytes and add the terminator "
    "yourself. Use only the public API declared in the headers shown, never internal "
    "symbols. If the entry needs an object (a struct pointer), build it with the library's own "
    "constructor or parser from the bytes; never fabricate struct contents by hand."
)


def llm_prompt(index: CodeIndex, entry: Function, target: Function, pre: Preconditions,
               include: Optional[str]) -> str:
    root = index.root
    declaration = f'#include "{Path(include).name}"' if include else _prototype(entry)
    src = (root / entry.file).read_text(errors="replace").splitlines()
    body = "\n".join(src[entry.start_line - 1: entry.end_line])
    parts = [f"ENTRY function (call this): {entry.name} in {entry.file}",
             f"It must reach the flagged function: {target.name}",
             "Declaration to use: " + declaration,
             "", "ENTRY source:", "```c", body[:6000], "```"]
    sites = index.callers_of(entry.name)[:3]
    for s in sites:
        lines = (root / s.file).read_text(errors="replace").splitlines()
        lo, hi = max(0, s.line - 8), min(len(lines), s.line + 4)
        parts += ["", f"A real caller ({s.caller} in {s.file}:{s.line}):", "```c",
                  "\n".join(lines[lo:hi]), "```"]
    if pre.call_sites:
        parts += ["", "Preconditions observed at the real call sites:"] + [f"- {d}" for d in pre.describe()]
    return "\n".join(parts)


def extract_c_block(text: str) -> str:
    m = re.search(r"```(?:c|C)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"


def synthesize(index: CodeIndex, target: Function, llm=None,
               max_paths: int = 3) -> list[Harness]:
    """
    Candidate harnesses for `target`, most deterministic first. The caller
    compiles each in turn and keeps the first that builds, is fair and reaches.
    Raises HarnessUnavailable with the reason if none can even be drafted.
    """
    paths = call_path_to(index, target)
    if not paths:
        raise HarnessUnavailable(
            f"{target.name}() is static and no externally callable function reaches it "
            f"within 3 call levels")
    out: list[Harness] = []
    reasons = []
    for path in paths[:max_paths]:
        entry = path[0]
        pre = mine_preconditions(index, entry)
        include = index.header_declaring(entry.name) if not entry.is_static else None
        slots = plan_slots(entry, pre)
        if slots is not None:
            src = render_template(entry, slots, include)
            problems = fairness_violations(src, entry, pre)
            if problems:                      # a template that is unfair is a bug: say so
                reasons.append(f"template for {entry.name} failed fairness: {problems[0]}")
            else:
                out.append(Harness(entry=entry, target=target, source=src, method="template",
                                   preconditions=pre, seeds=seeds_for(slots),
                                   call_path=[f.name for f in path],
                                   notes=[f"template slots: {', '.join(s.kind for s in slots)}"]
                                   + pre.describe()))
                continue
        else:
            reasons.append(f"{entry.name}({', '.join(p.text for p in entry.params)}): "
                           "parameter shape not covered by templates")
        if llm is not None:
            out.append(Harness(entry=entry, target=target, source="", method="llm",
                               preconditions=pre, call_path=[f.name for f in path],
                               notes=pre.describe() + [f"include: {include or 'prototype'}"]))
    if not out:
        raise HarnessUnavailable("; ".join(reasons) + ("" if llm is not None else
                                 "; LLM drafting disabled"))
    return out


def draft_with_llm(index: CodeIndex, h: Harness, llm, compile_error: str = "") -> str:
    include = index.header_declaring(h.entry.name) if not h.entry.is_static else None
    prompt = llm_prompt(index, h.entry, h.target, h.preconditions or Preconditions(), include)
    if compile_error:
        prompt += ("\n\nYour previous harness failed to compile or was rejected:\n"
                   + compile_error[:2000] + "\nReturn a corrected harness.")
    text = llm.complete(LLM_SYSTEM, prompt, purpose="harness", max_tokens=1500)
    return extract_c_block(text)
