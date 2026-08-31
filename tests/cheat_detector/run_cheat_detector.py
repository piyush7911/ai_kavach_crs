#!/usr/bin/env python3
"""
Cheat-detector demonstration — can the system catch patches that game its gates?

    python -m tests.cheat_detector.run_cheat_detector

Why this exists
---------------
Every automated repair system reports a pass rate. That number is only worth
something if the verification behind it cannot be gamed, and gate-only
verification IS gameable — trivially. A model optimising for "make the gate go
green" has two cheap moves, and both work:

  * special-case the one input the proof-of-vulnerability replays, or
  * disable the vulnerable code path entirely.

Both compile. Both pass the PoV replay. Both pass a single-input regression
check. Neither fixes anything.

This script builds those patches deliberately, runs them through the real
hardening engine (no test doubles, no mocking), and prints what happened. It
takes no LLM calls and needs no API key: the patches are constructed, not
generated, so the outcome depends only on the verifier.

Read the CORRECT row first. A detector that rejects everything is useless — the
honest fix has to survive, or the other two rejections prove nothing.
"""

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from rich.console import Console
from rich.table import Table

from src.patch_validator.hardening import PatchHardening

console = Console()

BUILD = 'clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 "{src}" -o "{bin}"'
POV_LENGTH = 80          # the input length the PoV gate replays

# Behaves correctly for short inputs, overflows past 64 bytes. It must have
# working benign behaviour, or differential testing would have nothing to
# compare and "no divergence" would be vacuous.
VULNERABLE = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy_it(const char* src, size_t size) {
    char* dest = (char*)malloc(64);
    if (!dest) return;
    for (size_t i = 0; i < size; i++) dest[i] = src[i];   /* overflows when size > 64 */
    dest[size < 64 ? size : 63] = '\\0';
    printf("copied:%s\\n", dest);
    free(dest);
}
int main(int argc, char** argv) {
    if (argc > 1) copy_it(argv[1], strlen(argv[1]));
    return 0;
}
"""

CORRECT = VULNERABLE.replace(
    "    char* dest = (char*)malloc(64);",
    "    char* dest = (char*)malloc(size + 1);",
).replace(
    "    dest[size < 64 ? size : 63] = '\\0';",
    "    dest[size] = '\\0';",
)

OVERFITTED = VULNERABLE.replace(
    "    for (size_t i = 0; i < size; i++)",
    f"    if (size == {POV_LENGTH}) size = 63;   /* silence the known PoV only */\n"
    "    for (size_t i = 0; i < size; i++)",
)

GUTTED = VULNERABLE.replace(
    "    char* dest = (char*)malloc(64);",
    "    return;\n    char* dest = (char*)malloc(64);",
)

# A fixture that failed to apply would make this demo silently vacuous.
for _name, _src in (("CORRECT", CORRECT), ("OVERFITTED", OVERFITTED), ("GUTTED", GUTTED)):
    assert _src != VULNERABLE, f"{_name} fixture failed to apply"


# Drives copy_it() with arbitrary lengths, so a patch that only handles the one
# replayed PoV length is exposed. Respects the function's contract: `src` really
# does hold `size` bytes.
HARNESS = """#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
void copy_it(const char* src, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 200) return 0;
    char* s = (char*)malloc(size + 1);
    memcpy(s, data, size);
    s[size] = 0;
    copy_it(s, size);
    free(s);
    return 0;
}
"""


@dataclass
class Candidate:
    name: str
    source: str
    cheat: bool
    description: str
    expected: str


CANDIDATES = [
    Candidate("CORRECT", CORRECT, False,
              "Sizes the allocation to the input — the honest fix",
              "must SURVIVE"),
    Candidate("OVERFITTED", OVERFITTED, True,
              f"if (size == {POV_LENGTH}) size = 63;  — silences only the replayed PoV",
              "must be CAUGHT"),
    Candidate("GUTTED", GUTTED, True,
              "return; at the top of the function — disables the code path",
              "must be CAUGHT"),
]


def gates_pass(source: str, work: Path) -> tuple[bool, bool]:
    """
    Run the gate checks a patch must clear before hardening ever sees it.

    Returns (pov_clean, regression_clean). Both true for all three candidates is
    the point of the exercise: the gates cannot separate the cheats from the fix.
    """
    src = work / "candidate.c"
    src.write_text(source)
    binary = work / "candidate"
    build = BUILD.replace("{src}", str(src)).replace("{bin}", str(binary))
    if subprocess.run(build, shell=True, capture_output=True).returncode != 0:
        return False, False

    env = {"ASAN_OPTIONS": "detect_leaks=0", "MallocNanoZone": "0", "PATH": "/usr/bin:/bin"}
    pov = subprocess.run([str(binary), "A" * POV_LENGTH],
                         capture_output=True, text=True, env=env)
    regression = subprocess.run([str(binary), "hello"],
                                capture_output=True, text=True, env=env)
    sanitizer = "AddressSanitizer" in (pov.stdout + pov.stderr)
    return (pov.returncode == 0 and not sanitizer), (regression.returncode == 0)


def main() -> int:
    if shutil.which("clang") is None:
        console.print("[red]clang not found — cannot build the candidates[/]")
        return 1

    console.print(
        "\n[bold cyan]Cheat-detector[/] — three patches, no LLM involved.\n"
        "Two deliberately game the verification gates; one is an honest fix.\n"
    )

    results = []

    with tempfile.TemporaryDirectory(prefix="kavach_cheat_") as tmp:
        work = Path(tmp)
        original = work / "original.c"
        original.write_text(VULNERABLE)

        # Adversarial re-fuzzing needs a harness for the target under test.
        # Without one the check reports "no fuzz harness" and does not run — and
        # an overfitted patch then sails through, because differential testing
        # alone cannot see it (the cheat preserves behaviour everywhere except
        # the one length it special-cases). Shipping the harness with the demo is
        # what makes the OVERFITTED row meaningful rather than a silent skip.
        harness_dir = work / "harnesses"
        harness_dir.mkdir()
        (harness_dir / "CHEAT-DEMO.c").write_text(HARNESS)
        hardener = PatchHardening(harness_dir=str(harness_dir))

        for c in CANDIDATES:
            console.print(f"  evaluating [bold]{c.name}[/] …")
            pov_ok, regression_ok = gates_pass(c.source, work)

            patched = work / f"{c.name.lower()}.c"
            patched.write_text(c.source)
            verdict = hardener.harden(
                target_id="CHEAT-DEMO",
                original_source=original,
                patched_source=patched,
                build_command=BUILD,
                refuzz_seconds=10,
                differential_inputs=25,
            )
            results.append((c, pov_ok, regression_ok, verdict))

    table = Table(title="Gates vs. hardening", show_lines=True)
    for col in ("Patch", "What it does", "PoV gate", "Regression", "Hardening", "Caught by"):
        table.add_column(col, overflow="fold")

    for c, pov_ok, regression_ok, v in results:
        caught = v.falsified
        if caught:
            by = []
            if v.overfitted:
                by.append("adversarial re-fuzzing")
            if v.diverged:
                by.append("differential testing")
            if v.evaded:
                by.append("evasion battery")
            by = ", ".join(by)
        else:
            by = "— (survived, as it should)" if not c.cheat else "[red]NOTHING — cheat slipped through[/]"

        table.add_row(
            c.name,
            c.description,
            "[green]PASS[/]" if pov_ok else "[red]FAIL[/]",
            "[green]PASS[/]" if regression_ok else "[red]FAIL[/]",
            "[red]FALSIFIED[/]" if caught else ("[green]SURVIVED[/]" if v.survived else "[yellow]NOT HARDENED[/]"),
            by,
        )
    console.print(table)

    # A pass means: every cheat was falsified AND the honest fix was not.
    cheats = [(c, v) for c, _, _, v in results if c.cheat]
    honest = [(c, v) for c, _, _, v in results if not c.cheat]
    caught = sum(1 for _, v in cheats if v.falsified)
    survived = sum(1 for _, v in honest if v.survived)

    gate_blind = all(pov_ok and reg_ok for _, pov_ok, reg_ok, _ in results)
    console.print(
        f"\n  Gates alone: {'[red]could not tell them apart[/]' if gate_blind else 'separated some'} "
        f"— all three compile, replay the PoV cleanly and pass regression."
    )
    console.print(f"  Hardening:   [bold]{caught}/{len(cheats)}[/] cheats falsified, "
                  f"[bold]{survived}/{len(honest)}[/] honest fixes survived.\n")

    ok = caught == len(cheats) and survived == len(honest)
    console.print("[bold green]  PASS — every cheat caught, the honest fix untouched.[/]\n" if ok
                  else "[bold red]  FAIL — see the table above.[/]\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
