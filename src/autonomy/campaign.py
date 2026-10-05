"""
Campaign stage: judge that the harness reaches the flagged function, fuzz, and
capture the behaviour oracle the repair gates will use.

Reach judge
-----------
A harness that compiles proves nothing: it may return before calling into the
library. The success criterion is that **the flagged function actually runs**.
libFuzzer's `-print_coverage=1` lists every covered function at exit, so the
judge runs a short bounded campaign and reads that list. "Gained some coverage"
is deliberately not accepted: the entry point alone would satisfy it.

If the bounded run crashes before it can print coverage, the crash itself is the
evidence, but only if the flagged function appears in its stack.

Behaviour oracle
----------------
An uploaded repository comes with no test command, so "the patch did not break
anything" would otherwise be unmeasured. The harness prints what the call
returned and what it wrote when `KAVACH_TRACE` is set. The ORIGINAL binary is
replayed on every corpus input it handles cleanly and that behaviour is recorded;
a patch is then required to reproduce it. This is the same differential idea as
the hardening stage, made available to the regression gate.
"""

import hashlib
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.autonomy import execute

_COVERED = re.compile(r"^COVERED_FUNC:\s+hits:\s*(\d+)\s+edges:\s*(\d+)/(\d+)\s+(\S+)\s+(\S+)", re.M)
_SANITIZER_ERROR = re.compile(r"ERROR:\s+(?:Address|Undefined|Leak)Sanitizer|runtime error:")
_RUNS = re.compile(r"Done\s+(\d+)\s+runs\s+in\s+(\d+)\s+second")
_COV = re.compile(r"\bcov:\s*(\d+)")
_CRASH_FILE = re.compile(r"^(crash|oom|timeout)-")

FUZZ_TIMEOUT = 5          # seconds a single input may run
RSS_LIMIT_MB = 2048


@dataclass
class ReachResult:
    reached: bool
    judged: bool = True              # False: the judge could not run, which is NOT the same as "not reached"
    covered: list[str] = field(default_factory=list)
    crashed: bool = False
    crash_input: str = ""
    detail: str = ""
    seconds: float = 0.0
    output_tail: str = ""            # the sanitizer report, when the check itself crashed

    def to_dict(self) -> dict:
        return {"reached": self.reached, "judged": self.judged, "functions_covered": len(self.covered),
                "crashed": self.crashed, "detail": self.detail, "seconds": self.seconds}


@dataclass
class FuzzResult:
    ran: bool
    crashes: list[Path] = field(default_factory=list)
    runs: int = 0
    seconds: float = 0.0
    coverage: int = 0
    exit_code: Optional[int] = None
    timed_out: bool = False
    stderr_tail: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {"ran": self.ran, "crashes": [c.name for c in self.crashes], "runs": self.runs,
                "seconds": self.seconds, "coverage": self.coverage, "exit_code": self.exit_code,
                "timed_out": self.timed_out, "note": self.note}


@dataclass
class GoldenEntry:
    path: str
    exit_code: int
    stdout_sha1: str


# -- seeds and corpus ---------------------------------------------------------------------

def write_seeds(seed_dir: Path, seeds: list[bytes], extra_dirs: Optional[list[Path]] = None,
                limit: int = 200) -> list[Path]:
    """Seed corpus: the harness's own seeds plus any data files the repository ships."""
    seed_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for i, data in enumerate(seeds):
        p = seed_dir / f"seed-{i:03d}"
        p.write_bytes(data)
        out.append(p)
    for d in extra_dirs or []:
        for f in sorted(d.rglob("*")):
            if len(out) >= limit:
                break
            if f.is_file() and not f.is_symlink() and f.stat().st_size <= 1 << 16:
                p = seed_dir / f"repo-{len(out):03d}"
                p.write_bytes(f.read_bytes())
                out.append(p)
    return out


# -- reach judge ----------------------------------------------------------------------------

def llvm_tools(fuzz_clang: str) -> Optional[tuple[str, str]]:
    """(llvm-profdata, llvm-cov) beside the fuzzer-capable clang, or None if either is missing."""
    d = Path(fuzz_clang).resolve().parent
    prof, cov = d / "llvm-profdata", d / "llvm-cov"
    return (str(prof), str(cov)) if prof.exists() and cov.exists() else None


def _covered_functions(export_json: str) -> list[str]:
    """Names of functions executed at least once, from `llvm-cov export` JSON."""
    import json
    try:
        data = json.loads(export_json)
        functions = data["data"][0]["functions"]
    except (ValueError, KeyError, IndexError):
        return []
    return [f["name"] for f in functions if f.get("count", 0) > 0]


def reach_check(reach_binary: Path, target: str, workdir: Path, seed_dir: Path,
                tools: Optional[tuple[str, str]], runs: int = 4000, timeout: int = 90) -> ReachResult:
    """
    Bounded run of a COVERAGE build; the flagged function must have executed.

    libFuzzer's own `-print_coverage` is not used: on macOS it prints an empty
    report. LLVM source-based coverage names every function, statics included
    (as `file.c:name`), and works the same on Linux.
    """
    if tools is None:
        return ReachResult(False, judged=False,
                           detail="llvm-profdata / llvm-cov not found beside the fuzzer-capable "
                                  "clang, so reach could not be judged")
    prof, cov = tools
    corpus = workdir / "reach_corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    raw = workdir / "reach.profraw"
    merged = workdir / "reach.profdata"
    raw.unlink(missing_ok=True)

    cmd = (f'{shlex.quote(str(reach_binary))} -runs={runs} -seed=1 -timeout={FUZZ_TIMEOUT} '
           f'-rss_limit_mb={RSS_LIMIT_MB} -close_fd_mask=1 '
           f'-artifact_prefix={shlex.quote(str(workdir) + "/reach_")} '
           f'{shlex.quote(str(corpus))} {shlex.quote(str(seed_dir))}')
    r = execute.run(cmd, workdir, timeout=timeout, env={"LLVM_PROFILE_FILE": str(raw)})
    if not r.ran:
        return ReachResult(False, judged=False, detail=f"not run: {r.note}")
    if r.timed_out:
        return ReachResult(False, judged=False, detail=f"reach check timed out after {timeout}s",
                           seconds=r.seconds)

    if _SANITIZER_ERROR.search(r.output):
        crash = next(iter(sorted(workdir.glob("reach_crash-*"))), None)
        in_stack = bool(re.search(r"\b" + re.escape(target) + r"\b", r.output))
        return ReachResult(
            reached=in_stack, crashed=True, crash_input=str(crash) if crash else "",
            seconds=r.seconds, output_tail=r.output[-1800:],
            detail=("crashed during the reach check, and the flagged function is in the stack"
                    if in_stack else
                    "crashed during the reach check, but the flagged function is not in the stack"))

    if not raw.exists():
        return ReachResult(False, judged=False, seconds=r.seconds,
                           detail="the coverage build wrote no profile (the binary may have been "
                                  "killed or the build lacked coverage instrumentation)")
    m = execute.run(f'{shlex.quote(prof)} merge -sparse {shlex.quote(str(raw))} -o {shlex.quote(str(merged))}',
                    workdir, timeout=60)
    if not m.ok:
        return ReachResult(False, judged=False, detail="llvm-profdata merge failed: " + m.output[-160:])
    x = execute.run(f'{shlex.quote(cov)} export {shlex.quote(str(reach_binary))} '
                    f'-instr-profile={shlex.quote(str(merged))}', workdir, timeout=60)
    covered = _covered_functions(x.stdout)
    if not covered:
        return ReachResult(False, judged=False, seconds=r.seconds,
                           detail="llvm-cov reported no executed functions")

    hit = next((c for c in covered if c == target or c.endswith(":" + target)), None)
    if hit:
        return ReachResult(True, covered=covered, seconds=r.seconds,
                           detail=f"{target} executed ({len(covered)} functions covered)")
    return ReachResult(False, covered=covered, seconds=r.seconds,
                       detail=f"{target} was never executed in {runs} runs; covered: "
                              f"{', '.join(covered[:6])}{' …' if len(covered) > 6 else ''}")


# -- fuzzing -------------------------------------------------------------------------------------

def fuzz(binary: Path, workdir: Path, seconds: int, seed_dir: Path,
         corpus: Optional[Path] = None, ignore_crashes: bool = False) -> FuzzResult:
    """
    A time-boxed libFuzzer campaign. Crash artefacts are files in `workdir/crashes`.
    `ignore_crashes` keeps fuzzing past a crash (fork mode), used when re-fuzzing a patch
    so that one unrelated, already-known bug cannot end the campaign early.
    """
    corpus = corpus or (workdir / "corpus")
    crashes = workdir / "crashes"
    corpus.mkdir(parents=True, exist_ok=True)
    crashes.mkdir(parents=True, exist_ok=True)
    cmd = (f'{shlex.quote(str(binary))} -max_total_time={seconds} -seed=1337 '
           f'-timeout={FUZZ_TIMEOUT} -rss_limit_mb={RSS_LIMIT_MB} -print_final_stats=1 -close_fd_mask=1 '
           f'{"-fork=1 -ignore_crashes=1 " if ignore_crashes else ""}'
           f'-artifact_prefix={shlex.quote(str(crashes) + "/")} '
           f'{shlex.quote(str(corpus))} {shlex.quote(str(seed_dir))}')
    r = execute.run(cmd, workdir, timeout=seconds + 60)
    if not r.ran:
        return FuzzResult(ran=False, note=r.note)

    found = sorted(p for p in crashes.iterdir() if _CRASH_FILE.match(p.name))
    runs = _RUNS.search(r.output)
    cov = [int(c) for c in _COV.findall(r.output)]
    return FuzzResult(
        ran=True, crashes=found, runs=int(runs.group(1)) if runs else 0, seconds=r.seconds,
        coverage=max(cov) if cov else 0, exit_code=r.code, timed_out=r.timed_out,
        stderr_tail="\n".join(r.stderr.strip().splitlines()[-10:]), note=r.note)


# -- replay and the behaviour oracle ---------------------------------------------------------------

def replay(binary: Path, input_path: Path, workdir: Path, trace: bool = True,
           timeout: int = 30) -> execute.ExecResult:
    """Run the binary once on one input (libFuzzer replays a file argument)."""
    env = {"KAVACH_TRACE": "1"} if trace else {}
    return execute.run(f'{shlex.quote(str(binary))} {shlex.quote(str(input_path))}',
                       workdir, timeout=timeout, env=env)


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def capture_golden(binary: Path, inputs: list[Path], workdir: Path, limit: int = 60) -> list[GoldenEntry]:
    """
    Record the ORIGINAL binary's behaviour on inputs it handles cleanly.

    An input on which the original already crashes carries no expectation, so it
    is not recorded: what a patch should do there is "not crash", which the PoV
    gate and re-fuzzing already test.
    """
    golden = []
    for path in sorted(inputs)[:limit]:
        r = replay(binary, path, workdir)
        if not r.ran or r.timed_out or r.code != 0 or _SANITIZER_ERROR.search(r.output):
            continue
        # replay_check.sh captures stdout with $(...), which drops trailing newlines;
        # hash the same bytes or the ORIGINAL fails its own check.
        golden.append(GoldenEntry(str(path.resolve()), 0, _sha1(r.stdout.rstrip("\n"))))
    return golden


def write_golden(golden: list[GoldenEntry], path: Path) -> Path:
    """TSV: sha1 of stdout, exit code, input path. Read by replay_check.sh."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{g.stdout_sha1}\t{g.exit_code}\t{g.path}\n" for g in golden))
    return path


REPLAY_CHECK_SH = r'''#!/bin/sh
# Behaviour regression gate for autonomous mode.
#   usage: replay_check.sh <binary> <golden.tsv>
# Replays every recorded input on the (patched) binary with KAVACH_TRACE=1 and
# requires the same exit code and the same stdout hash as the ORIGINAL produced.
# Exit 0: behaviour preserved.  Exit 1: it changed (the first difference is printed).
BIN="$1"; GOLD="$2"
if [ ! -x "$BIN" ] || [ ! -s "$GOLD" ]; then echo "replay_check: missing binary or golden file" >&2; exit 2; fi
if command -v shasum >/dev/null 2>&1; then H="shasum"; else H="sha1sum"; fi
checked=0
while IFS="$(printf '\t')" read -r want_sha want_rc path; do
  [ -z "$path" ] && continue
  # A patched binary that hangs must fail in seconds. The parent perl SIGKILLs the child
  # (libFuzzer/ASan binaries swallow SIGALRM, so alarm+exec alone never fires).
  out=$(ASAN_OPTIONS=detect_leaks=0 KAVACH_TRACE=1 perl -e '$t=shift; $p=fork; if(!$p){exec @ARGV; exit 127} $SIG{ALRM}=sub{kill 9,$p; waitpid($p,0); exit 142}; alarm $t; waitpid($p,0); $s=$?; exit($s&127 ? 128+($s&127) : $s>>8)' 10 "$BIN" "$path" 2>/dev/null); rc=$?
  if [ "$rc" = 142 ]; then echo "REGRESSION: input $path makes the patched binary hang (over 10 s)"; exit 1; fi
  got_sha=$(printf '%s' "$out" | $H | cut -d' ' -f1)
  checked=$((checked+1))
  if [ "$rc" != "$want_rc" ]; then
    echo "REGRESSION: input $path now exits $rc (the original exited $want_rc)"; exit 1
  fi
  if [ "$got_sha" != "$want_sha" ]; then
    echo "REGRESSION: input $path now behaves differently (return value or output changed)"; exit 1
  fi
done < "$GOLD"
echo "behaviour preserved on $checked recorded input(s)"
'''


def write_replay_check(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(REPLAY_CHECK_SH)
    path.chmod(0o755)
    return path


def compare_behaviour(original: Path, patched: Path, inputs: list[Path], workdir: Path,
                      limit: int = 150) -> tuple[int, list[str]]:
    """
    Differential test on arbitrary inputs: where the ORIGINAL is clean, the
    patched binary must behave identically. Returns (inputs compared, differences).
    """
    compared, diffs = 0, []
    for path in sorted(inputs)[:limit]:
        a = replay(original, path, workdir)
        if not a.ran or a.timed_out or a.code != 0 or _SANITIZER_ERROR.search(a.output):
            continue                        # the original is not clean here: nothing to preserve
        b = replay(patched, path, workdir)
        compared += 1
        if b.code != a.code or _sha1(b.stdout) != _sha1(a.stdout):
            diffs.append(f"{path.name}: exit {a.code}→{b.code}"
                         + ("" if _sha1(b.stdout) == _sha1(a.stdout) else ", output differs"))
    return compared, diffs
