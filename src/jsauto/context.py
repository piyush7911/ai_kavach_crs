"""
Build what the repair model is shown for one JavaScript finding, and keep what is needed to splice its
answer back.

The model sees: what class of bug it is and how that class is fixed (generic guidance), where the user
data enters (route and request field), the call chain it travels, and the FULL text of the function to
fix, between markers, with line numbers. It is asked for the complete replacement of exactly that unit.
Showing the chain matters because the bug is often one function away from where the data arrives; fixing
only the sink and being told so is how a model ends up validating the wrong thing.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.jsauto import patch

GUIDANCE_PATH = Path(__file__).resolve().parents[2] / "config" / "js_fix_guidance.json"
MAX_UNIT_CHARS = 7000
MAX_TOTAL_CHARS = 16000

SYSTEM = (
    "You repair security vulnerabilities in Node.js code. You are given ONE function to fix, between the "
    "markers FIX-BEGIN and FIX-END. Reply with the complete replacement for exactly that code, in a single "
    "```js block, and nothing else. Rules: keep the function's name, parameters and behaviour for legitimate "
    "input; change only what the fix needs; do not add dependencies, do not edit other functions, do not "
    "remove checks, do not swallow errors, and do not special-case the exact input that triggers the problem. "
    "Add any `require` the fix needs inside the function."
)


@dataclass
class Prepared:
    file: str
    unit: Optional[patch.Unit]
    prompt: str
    problem: str = ""              # set when the target could not be located


def guidance(klass: str, path: Path = GUIDANCE_PATH) -> str:
    g = json.loads(Path(path).read_text())
    return f"{g.get(klass, '')} {g['_generic']}".strip()


def _numbered(text: str, first_line: int) -> str:
    return "\n".join(f"{first_line + i:>4}| {l}" for i, l in enumerate(text.splitlines()))


def _unit_text(root: Path, rel: str, function: str, line: int = 0):
    path = root / rel
    if not path.exists():
        return None, None
    src = path.read_text(errors="replace")
    return patch.find_unit(src, function, line), src


def prepare(finding: dict, root: Path) -> Prepared:
    """The prompt and splice target for one finding (a dict, as `Finding.to_dict()`)."""
    root = Path(root)
    rel, fn, line = finding["file"], finding.get("function", ""), finding.get("line", 0)
    unit, _ = _unit_text(root, rel, fn, line)
    if unit is None:
        return Prepared(rel, None, "", f"cannot locate function {fn!r} in {rel}")
    ev = finding.get("evidence") or {}
    entry = ev.get("entry") or {}
    route = entry.get("route") or {}
    parts = [
        f"VULNERABILITY: {finding.get('klass')} ({finding.get('cwe') or 'no CWE'}), severity {finding.get('severity')}",
        f"FINDING: {finding.get('message', '')}",
    ]
    if route:
        parts.append(f"ENTRY POINT: {route.get('method')} {route.get('path')} handled by "
                     f"{entry.get('function')} in {entry.get('file')}")
    if ev.get("tainted_expr"):
        parts.append(f"USER DATA: `{ev['tainted_expr']}` reaches {ev.get('callee', 'the vulnerable call')}")
    parts += ["", "HOW THIS CLASS IS FIXED: " + guidance(finding.get("klass", "")), ""]

    chain = [c for c in (ev.get("chain") or [])]
    shown = 0
    for hop in chain[:-1]:                                    # the functions the data passed through
        hop_file, _, hop_fn = hop.partition(":")
        u, _ = _unit_text(root, hop_file, hop_fn)
        if u is None or (hop_file == rel and hop_fn == fn):
            continue
        text = u.text[:MAX_UNIT_CHARS]
        parts += [f"CONTEXT (do not change): {hop_file} `{hop_fn}`", "```js", _numbered(text, u.start_line), "```", ""]
        shown += len(text)
        if shown > MAX_TOTAL_CHARS // 2:
            break

    fix_text = unit.text[:MAX_UNIT_CHARS]
    parts += [f"FIX THIS ({rel}, lines {unit.start_line}-{unit.end_line}):", "FIX-BEGIN", "```js",
              _numbered(fix_text, unit.start_line), "```", "FIX-END"]
    if len(unit.text) > MAX_UNIT_CHARS:
        parts.append("(the function is longer than shown; keep the part that is not shown unchanged)")
    return Prepared(rel, unit, "\n".join(parts)[:MAX_TOTAL_CHARS])


def apply_answer(root: Path, prepared: Prepared, model_response: str) -> tuple[Optional[str], list[str]]:
    """
    Splice the model's answer into the file. Returns (new file text, violations). On any violation the
    text is None and the reasons are what the model is told on its next attempt.
    """
    if prepared.unit is None:
        return None, [prepared.problem or "no target"]
    path = Path(root) / prepared.file
    before = path.read_text(errors="replace")
    replacement = patch.extract_code(model_response)
    if not replacement.strip():
        return None, ["the answer contained no code"]
    after = patch.splice(before, prepared.unit, replacement)
    problems = patch.check_patch(prepared.file, before, after,
                                 prepared.unit.function_start_line, prepared.unit.function_end_line)
    return (None, problems) if problems else (after, [])
