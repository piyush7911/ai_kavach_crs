"""
Autonomous mode, step 1 — ingest: snapshot, census, build detection.

The repository is copied into the run directory before anything touches it, so
every later stage (and the evidence bundle) refers to an immutable snapshot
whose hash is recorded, and the user's checkout is never modified.

Build detection decides how the library gets compiled into a fuzzable form.
Auto mode does not drive the project's own build to produce a binary: it needs
sanitizer- and coverage-instrumented objects it can link a harness against. So
it compiles the project's C sources itself ("direct compile") and uses the
build system only for what direct compilation cannot do on its own:

  flat-c   no build system: compile the sources as they are.
  make     Makefile project: if a `configure` script exists it is run first
           (sandboxed when a sandbox is on) to generate config headers.
  cmake    CMake project: `cmake -S . -B <build>` configures (no build) to
           generate config headers; the build dir is added to the include path.
  unknown  anything else (meson, bazel, autotools without configure, ...):
           auto mode refuses unless `--build-cmd` supplies a preparation
           command, and says so.

Whatever is detected, the user's `--build-cmd` (if given) runs as the
preparation step instead.
"""

import hashlib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SOURCE_EXT = {".c"}
HEADER_EXT = {".h"}
CXX_EXT = {".cc", ".cpp", ".cxx"}
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__", "build", "_build",
             "cmake-build-debug", "cmake-build-release", ".tmp"}
MAX_SNAPSHOT_BYTES = 400 * 1024 * 1024

# Source files that are almost never part of the library proper. They are
# still compiled into the archive (a renamed `main` makes them harmless), but
# they are not offered as fuzz targets.
_NON_LIBRARY = re.compile(r"(^|/)(tests?|testing|examples?|demos?|contrib|bench(mark)?s?|"
                          r"tools?|fuzz(ing|ers?)?|win32|windows|msdos|os2|amiga|vms|qnx|watcom)(/|$)",
                          re.IGNORECASE)
_MAIN = re.compile(r"^\s*(int|void)\s+main\s*\(", re.MULTILINE)
_LIBFUZZER_ENTRY = re.compile(r"\bLLVMFuzzerTestOneInput\s*\(")


class IngestError(RuntimeError):
    """The repository cannot be analysed as given. The message says why."""


@dataclass
class Census:
    files: int = 0
    c_files: int = 0
    header_files: int = 0
    cxx_files: int = 0
    lines_of_code: int = 0
    files_with_main: list[str] = field(default_factory=list)
    existing_harnesses: list[str] = field(default_factory=list)
    build_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class BuildPlan:
    kind: str                       # flat-c | make | cmake | custom | unknown
    note: str
    prepare_command: str = ""       # run once in the snapshot before compiling
    sources: list[str] = field(default_factory=list)       # relative to the snapshot
    include_dirs: list[str] = field(default_factory=list)  # relative to the snapshot
    defines: list[str] = field(default_factory=list)

    @property
    def library_sources(self) -> list[str]:
        """Sources that may be offered as fuzz targets (tests, tools, ports excluded)."""
        return [s for s in self.sources if not _NON_LIBRARY.search(s)]

    def to_dict(self) -> dict:
        return {"kind": self.kind, "note": self.note, "prepare_command": self.prepare_command,
                "sources": len(self.sources), "library_sources": len(self.library_sources),
                "include_dirs": self.include_dirs, "defines": self.defines}


@dataclass
class Snapshot:
    root: Path                     # the copy, inside the run directory
    origin: str                    # where it came from (shown, never re-read)
    sha256: str                    # over (relative path, content) of every copied file
    census: Census
    plan: BuildPlan


def _walk(root: Path):
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS or part.startswith("__MACOSX") for part in rel.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        yield path, rel


def snapshot(repo: Path, dest: Path) -> tuple[Path, str]:
    """Copy `repo` into `dest/<name>` (no symlinks, no VCS dirs); return (root, sha256)."""
    repo = repo.resolve()
    if not repo.is_dir():
        raise IngestError(f"target is not a directory: {repo}")
    root = dest / (repo.name or "repo")
    if root.exists():
        shutil.rmtree(root)
    digest = hashlib.sha256()
    total = 0
    for path, rel in _walk(repo):
        total += path.stat().st_size
        if total > MAX_SNAPSHOT_BYTES:
            raise IngestError(f"repository larger than {MAX_SNAPSHOT_BYTES // 2**20} MB")
        out = root / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        data = path.read_bytes()
        out.write_bytes(data)
        out.chmod(path.stat().st_mode & 0o777)
        digest.update(rel.as_posix().encode() + b"\0" + hashlib.sha256(data).digest())
    if total == 0:
        raise IngestError("repository is empty")
    return root, digest.hexdigest()


def take_census(root: Path) -> Census:
    c = Census()
    for path, rel in _walk(root):
        c.files += 1
        name, suffix = path.name, path.suffix.lower()
        relp = rel.as_posix()
        if name in ("Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "configure",
                    "configure.ac", "meson.build", "BUILD", "BUILD.bazel"):
            c.build_files.append(relp)
        if suffix in HEADER_EXT:
            c.header_files += 1
        elif suffix in CXX_EXT:
            c.cxx_files += 1
        elif suffix in SOURCE_EXT:
            c.c_files += 1
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            c.lines_of_code += text.count("\n") + 1
            if _MAIN.search(text):
                c.files_with_main.append(relp)
            if _LIBFUZZER_ENTRY.search(text):
                c.existing_harnesses.append(relp)
    c.build_files.sort()
    return c


def detect_build(root: Path, census: Census, build_cmd: str = "") -> BuildPlan:
    """Decide how auto mode will compile this repository. Never guesses silently."""
    sources, headers_dirs = [], set()
    for path, rel in _walk(root):
        relp = rel.as_posix()
        if path.suffix.lower() in SOURCE_EXT:
            if relp in census.existing_harnesses:
                continue          # harness files are linked on their own, never into the library
            sources.append(relp)
        elif path.suffix.lower() in HEADER_EXT:
            headers_dirs.add(rel.parent.as_posix() if rel.parent.as_posix() != "." else ".")
    includes = sorted(headers_dirs, key=lambda d: (d.count("/"), d))
    if "." not in includes:
        includes.insert(0, ".")

    names = {Path(b).name for b in census.build_files if "/" not in b}
    top_level = set(names)

    if not sources:
        if census.cxx_files:
            raise IngestError("only C++ sources found; autonomous mode currently handles C")
        raise IngestError("no C sources found")

    if build_cmd:
        return BuildPlan("custom", "preparation command supplied with --build-cmd",
                         build_cmd, sources, includes)
    if "CMakeLists.txt" in top_level:
        return BuildPlan(
            "cmake", "CMake project: configured (not built) to generate headers, then the "
                     "C sources are compiled directly with sanitizers.",
            'cmake -S . -B .kavach_cmake -DCMAKE_C_COMPILER="${CC:-clang}" >/dev/null',
            sources, includes + [".kavach_cmake"])
    if top_level & {"Makefile", "makefile", "GNUmakefile"} or "configure" in top_level:
        prep = "./configure >/dev/null" if "configure" in top_level else ""
        return BuildPlan(
            "make", "Makefile project: " + ("configure is run to generate headers, then " if prep
                                            else "") + "the C sources are compiled directly "
                                                       "with sanitizers.",
            prep, sources, includes)
    if top_level & {"meson.build", "BUILD", "BUILD.bazel", "configure.ac"}:
        raise IngestError(
            f"build system not supported for direct compilation ({', '.join(sorted(top_level))}). "
            "Pass --build-cmd with a command that generates any configured headers "
            "(for example `meson setup b`), and auto mode will compile the sources itself.")
    return BuildPlan("flat-c", "No build system: the C sources are compiled directly "
                               "with sanitizers.", "", sources, includes)


def ingest(repo: str, run_dir: Path, build_cmd: str = "") -> Snapshot:
    root, digest = snapshot(Path(repo), run_dir / "snapshot")
    census = take_census(root)
    plan = detect_build(root, census, build_cmd)
    return Snapshot(root=root, origin=str(Path(repo).resolve()), sha256=digest,
                    census=census, plan=plan)
