"""
AI Kavach CRS — patch policy gate.

The execution gates (build, PoV, regression, post-scan) ask "does the patched
program behave?". This gate asks a different question first: "is this the kind
of change a repair is allowed to be?". Several ways of gaming the execution
gates are cheaper to forbid by shape than to catch by behaviour — a signal
handler that turns a crash into exit 0, an attribute that switches the
sanitizer off, an edit to the regression script instead of the code.

Rules (each one reported by name, each one tested):

  single_file           only the flagged source file may change. Any other file
                        in the workspace changing is a violation.
  no_test_or_build_edit a change to a test, script or build file is called out
                        separately, because it is the specific cheat.
  in_flagged_function   every changed line lies inside the function that holds
                        the flagged line. Added `#include` lines are the one
                        allowed exception (a fix may need <stdint.h>).
  changed_line_cap      at most `max_changed_lines` lines differ.
  denied_construct      the patch may not ADD: signal()/sigaction(), any
                        no_sanitize attribute or sanitizer-disabling pragma,
                        inline assembly, exit()/_exit()/_Exit(), getenv(),
                        setjmp()/longjmp(). A construct already present in the
                        original is not counted against the patch.

The gate is pure (no compiler, no subprocess): it compares two texts and a
workspace snapshot. That keeps it fast enough to run before the build.

Switch: KAVACH_POLICY=off disables it (recorded as a skipped gate, never a pass).
"""

import difflib
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_MAX_CHANGED_LINES = 80

# (rule name, human description, pattern). Matched against ADDED lines only,
# with comments and string literals removed so `/* no signal() here */` and
# printf("exit(0)") do not trip it.
DENIED = [
    ("signal_handler", "installs a signal handler",
     re.compile(r"\b(signal|sigaction|sigset|bsd_signal)\s*\(|\bstruct\s+sigaction\b")),
    ("sanitizer_disabled", "disables sanitizer instrumentation",
     re.compile(r"no_sanitize|__no_sanitize|disable_sanitizer_instrumentation|"
                r"#\s*pragma\s+clang\s+attribute|__attribute__\s*\(\(\s*optnone")),
    ("inline_asm", "uses inline assembly",
     re.compile(r"\b(__asm__|__asm|asm)\s*(volatile|__volatile__)?\s*\(")),
    ("process_exit", "exits the process",
     re.compile(r"\b(exit|_exit|_Exit|quick_exit)\s*\(")),
    ("environment_bypass", "branches on the environment",
     re.compile(r"\b(getenv|secure_getenv)\s*\(")),
    ("nonlocal_jump", "uses setjmp/longjmp",
     re.compile(r"\b(setjmp|longjmp|sigsetjmp|siglongjmp)\s*\(")),
]

_TEST_OR_BUILD = re.compile(
    r"(^|/)(Makefile|makefile|GNUmakefile|CMakeLists\.txt|configure(\.ac)?|meson\.build|"
    r"BUILD(\.bazel)?|.*\.(sh|mk|cmake|py)|.*test.*|.*spec.*)$",
    re.IGNORECASE,
)

_INCLUDE = re.compile(r"^\s*#\s*include\s*[<\"][^>\"]+[>\"]\s*$")


@dataclass
class Violation:
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.detail}"


@dataclass
class PolicyResult:
    violations: list[Violation] = field(default_factory=list)
    changed_lines: int = 0
    function: str = ""

    @property
    def ok(self) -> bool:
        return not self.violations

    def feedback(self) -> str:
        lines = ["PATCH POLICY VIOLATION. The patch was not built or run because its "
                 "shape is not allowed for a repair:"]
        lines += [f"  - {v}" for v in self.violations]
        lines.append("Fix the defect inside the flagged function, in the flagged file "
                     "only, without signal handlers, sanitizer attributes, inline "
                     "assembly, process exits, environment checks or non-local jumps.")
        return "\n".join(lines)


def enabled() -> bool:
    return os.environ.get("KAVACH_POLICY", "on").strip().lower() != "off"


def _strip_comments_and_strings(line: str) -> str:
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(\\.|[^'\\])*'", "''", line)
    line = re.sub(r"/\*.*?\*/", " ", line)
    return line.split("//", 1)[0]


def snapshot(root: Path) -> dict[str, str]:
    """sha256 of every regular file under `root`, keyed by relative POSIX path."""
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            rel = p.relative_to(root).as_posix()
            if rel.startswith(".tmp/"):
                continue
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def changed_paths(before: dict[str, str], after: dict[str, str]) -> list[str]:
    keys = set(before) | set(after)
    return sorted(k for k in keys if before.get(k) != after.get(k))


def function_spans(source: str, language: str = "c") -> list[tuple[str, int, int]]:
    """(name, first_line, last_line), 1-indexed, for every function definition."""
    from src.context_engine.tree_sitter_extractor import ContextExtractor
    extractor = ContextExtractor()
    parser = extractor.cpp_parser if language == "cpp" else extractor.c_parser
    tree = parser.parse(source.encode("utf-8", errors="replace"))
    spans, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            spans.append((extractor._get_function_name(node),
                          node.start_point[0] + 1, node.end_point[0] + 1))
            continue                       # nested definitions are not C
        stack.extend(node.children)
    return sorted(spans, key=lambda s: s[1])


def _changes(original: str, patched: str):
    """
    Yield (orig_lo, orig_hi, added_lines, removed_lines) per changed block.
    Original line numbers are 1-indexed; a pure insertion has orig_lo > orig_hi
    and sits between lines orig_hi and orig_lo.
    """
    a, b = original.splitlines(), patched.splitlines()
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        yield i1 + 1, i2, b[j1:j2], a[i1:i2]


class PatchPolicy:
    """Shape rules a candidate patch must satisfy before it is built."""

    def __init__(self, max_changed_lines: int = DEFAULT_MAX_CHANGED_LINES):
        self.max_changed_lines = max_changed_lines

    def check(
        self,
        original: str,
        patched: str,
        target_rel: str = "",
        flagged_line: Optional[int] = None,
        workspace_changes: Optional[list[str]] = None,
        language: str = "c",
    ) -> PolicyResult:
        result = PolicyResult()

        # -- files ----------------------------------------------------------
        for path in workspace_changes or []:
            if target_rel and path == target_rel:
                continue
            if _TEST_OR_BUILD.search(path):
                result.violations.append(Violation(
                    "no_test_or_build_edit", f"modifies test or build file {path}"))
            else:
                result.violations.append(Violation(
                    "single_file", f"modifies {path}, which is not the flagged file"))

        changes = list(_changes(original, patched))

        # -- size -----------------------------------------------------------
        result.changed_lines = sum(len(add) + len(rem) for _, _, add, rem in changes)
        if result.changed_lines > self.max_changed_lines:
            result.violations.append(Violation(
                "changed_line_cap",
                f"{result.changed_lines} changed lines (cap {self.max_changed_lines})"))

        # -- denied constructs (added, not already present) -----------------
        before_text = "\n".join(_strip_comments_and_strings(l) for l in original.splitlines())
        after_text = "\n".join(_strip_comments_and_strings(l) for l in patched.splitlines())
        for rule, description, pattern in DENIED:
            hits = [line.strip()
                    for _, _, added, _ in changes for line in added
                    if pattern.search(_strip_comments_and_strings(line))]
            if not hits:
                continue
            # Only count constructs the original did not already contain as
            # often: re-indenting an existing exit() is not adding one.
            if len(pattern.findall(after_text)) <= len(pattern.findall(before_text)):
                continue
            result.violations.append(Violation(
                "denied_construct", f"{description} ({rule}): {hits[0][:120]}"))

        # -- location -------------------------------------------------------
        if changes:
            try:
                spans = function_spans(original, language)
            except Exception as e:                       # pragma: no cover - parser missing
                result.violations.append(Violation(
                    "in_flagged_function", f"cannot locate functions: {e}"))
                return result
            home = None
            if flagged_line:
                home = next((s for s in spans if s[1] <= flagged_line <= s[2]), None)
            if home is None:
                # No flagged line, or it is outside any function: the first
                # non-include change defines the one function allowed to change.
                for lo, hi, added, removed in changes:
                    if _include_only(added, removed):
                        continue
                    anchor = lo if lo <= hi else hi
                    home = next((s for s in spans if s[1] <= anchor <= s[2]), None)
                    break
            result.function = home[0] if home else ""
            for lo, hi, added, removed in changes:
                if _include_only(added, removed):
                    continue
                if home is None:
                    result.violations.append(Violation(
                        "in_flagged_function", "change is outside every function"))
                    break
                _, start, end = home
                if lo <= hi:
                    inside = start <= lo and hi <= end
                else:
                    # Pure insertion between original lines hi and lo: inside
                    # when it lands after the header and before the closing brace.
                    inside = start <= hi and lo <= end
                if not inside:
                    where = f"line {lo}" if lo <= hi else f"after line {hi}"
                    result.violations.append(Violation(
                        "in_flagged_function",
                        f"edit at {where} is outside {home[0]}() (lines {start}-{end})"))
                    break
        return result


def _include_only(added: list[str], removed: list[str]) -> bool:
    """A block that only adds #include lines (and maybe blank lines)."""
    if removed and any(l.strip() for l in removed):
        return False
    meaningful = [l for l in added if l.strip()]
    return bool(meaningful) and all(_INCLUDE.match(l) for l in meaningful)
