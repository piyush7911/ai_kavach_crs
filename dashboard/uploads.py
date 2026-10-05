"""
Accepting a repository from a browser: a zip, or a dropped folder.

A dropped archive is untrusted input and everything downstream will compile and
run code from it. So this module's only job is to land the files safely and
describe them, and it is strict about what "safely" means:

  * no path may escape the destination (zip-slip: `../x`, absolute paths,
    drive letters, backslash tricks);
  * no symlinks (a link can point outside the tree once extracted);
  * hard caps on file count, total size and single-file size, checked from the
    archive's declared sizes *and* enforced while writing, so a lying header
    cannot defeat them (zip bombs);
  * no execution of anything. Nothing here builds, runs or imports uploaded code.

The checks are pure functions so they can be tested without a web server.
"""

import re
import shutil
import stat
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = PROJECT_ROOT / "dashboard" / "uploads"

MAX_FILES = 20_000
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 50 * 1024 * 1024

SOURCE_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__"}


class UploadError(ValueError):
    """The upload was rejected. The message is safe to show the user."""


def safe_member_path(name: str) -> Optional[PurePosixPath]:
    """
    Normalise an archive member name, or return None if it must be rejected.

    Rejects absolute paths, parent traversal, Windows drive letters and backslash
    separators (which some extractors treat as path separators), and empty names.
    """
    if not name or "\x00" in name:
        return None
    if "\\" in name:
        return None
    p = PurePosixPath(name)
    if p.is_absolute() or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [x for x in p.parts if x not in ("", ".")]
    if not parts or any(x == ".." for x in parts):
        return None
    return PurePosixPath(*parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode) if mode else False


def validate_zip(zf: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    """Check an archive's members against every rule; return the (info, path) list to extract."""
    members = []
    total = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        path = safe_member_path(info.filename)
        if path is None:
            raise UploadError(f"unsafe path in archive: {info.filename!r}")
        if _is_symlink(info):
            raise UploadError(f"symbolic link in archive: {info.filename!r}")
        if info.file_size > MAX_FILE_BYTES:
            raise UploadError(f"file too large ({info.file_size // 2**20} MB): {info.filename!r}")
        total += info.file_size
        members.append((info, path))
        if len(members) > MAX_FILES:
            raise UploadError(f"too many files (limit {MAX_FILES})")
        if total > MAX_TOTAL_BYTES:
            raise UploadError(f"archive expands beyond {MAX_TOTAL_BYTES // 2**20} MB")
    if not members:
        raise UploadError("the archive contains no files")
    return members


def extract_zip(zip_path: Path, dest: Path) -> int:
    """Extract a validated archive into `dest`. Returns the number of files written."""
    dest = dest.resolve()
    written_total = 0
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        raise UploadError("not a valid zip file")
    with zf:
        members = validate_zip(zf)
        for info, rel in members:
            target = (dest / rel).resolve()
            # Belt and braces: even after normalisation, confirm containment.
            if dest != target and dest not in target.parents:
                raise UploadError(f"unsafe path in archive: {info.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(1 << 20):
                    written += len(chunk)
                    written_total += len(chunk)
                    # Enforce while writing: a header can lie about its size.
                    if written > MAX_FILE_BYTES or written_total > MAX_TOTAL_BYTES:
                        raise UploadError("archive expands beyond the size limit")
                    out.write(chunk)
    return len(members)


def new_repo_dir() -> tuple[str, Path]:
    repo_id = "r_" + time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:4]
    d = UPLOAD_DIR / repo_id
    d.mkdir(parents=True, exist_ok=False)
    return repo_id, d


def write_dropped_file(dest: Path, rel_name: str, data: bytes, state: dict) -> None:
    """Write one file from a dropped folder, applying the same rules as an archive."""
    rel = safe_member_path(rel_name)
    if rel is None:
        raise UploadError(f"unsafe path: {rel_name!r}")
    if len(data) > MAX_FILE_BYTES:
        raise UploadError(f"file too large: {rel_name!r}")
    state["files"] = state.get("files", 0) + 1
    state["bytes"] = state.get("bytes", 0) + len(data)
    if state["files"] > MAX_FILES:
        raise UploadError(f"too many files (limit {MAX_FILES})")
    if state["bytes"] > MAX_TOTAL_BYTES:
        raise UploadError(f"upload exceeds {MAX_TOTAL_BYTES // 2**20} MB")
    target = (dest.resolve() / rel).resolve()
    if dest.resolve() not in target.parents:
        raise UploadError(f"unsafe path: {rel_name!r}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def find_root(dest: Path) -> Path:
    """If everything sits in one top-level directory, that directory is the repo root."""
    entries = [e for e in dest.iterdir() if e.name not in SKIP_DIRS and not e.name.startswith("__MACOSX")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def census(root: Path) -> dict:
    """Describe what was uploaded, without running any of it."""
    ext_count: dict[str, int] = {}
    loc = 0
    mains = 0
    build_files: list[str] = []
    dirs: dict[str, int] = {}
    total_files = 0

    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        total_files += 1
        name, suffix = path.name, path.suffix.lower()
        if name in ("Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "configure",
                    "configure.ac", "meson.build", "BUILD", "BUILD.bazel", "Dockerfile"):
            build_files.append(str(path.relative_to(root)))
        if suffix in SOURCE_EXT:
            ext_count[suffix] = ext_count.get(suffix, 0) + 1
            top = path.relative_to(root).parts[0] if len(path.relative_to(root).parts) > 1 else "."
            dirs[top] = dirs.get(top, 0) + 1
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            loc += text.count("\n") + 1
            if re.search(r"\bint\s+main\s*\(", text):
                mains += 1

    c_files = sum(ext_count.get(e, 0) for e in (".c", ".cc", ".cpp", ".cxx"))
    names = {Path(b).name for b in build_files}
    if "CMakeLists.txt" in names:
        kind, note = "cmake", "CMake project: needs a configure step before the build."
    elif names & {"Makefile", "makefile", "GNUmakefile"}:
        kind, note = "make", "Makefile project: a build command can usually be `make`."
    elif c_files:
        kind, note = "flat-c", "No build system found: sources can be compiled directly."
    else:
        kind, note = "none", "No C or C++ sources found."

    return {
        "files": total_files, "source_files": sum(ext_count.values()),
        "extensions": ext_count, "lines_of_code": loc, "files_with_main": mains,
        "build_files": sorted(build_files)[:12], "build_kind": kind, "build_note": note,
        "top_dirs": sorted(dirs.items(), key=lambda kv: -kv[1])[:8],
    }


def describe(repo_id: str) -> Optional[dict]:
    if not re.fullmatch(r"r_[0-9]{8}_[0-9]{6}_[0-9a-f]{4}", repo_id):
        return None
    d = UPLOAD_DIR / repo_id
    if not d.is_dir():
        return None
    root = find_root(d)
    try:
        shown = str(root.relative_to(PROJECT_ROOT))
    except ValueError:               # upload directory configured outside the project
        shown = str(root)
    return {"repo_id": repo_id, "name": root.name if root != d else repo_id,
            "root": shown, "census": census(root)}


def list_repos() -> list[dict]:
    if not UPLOAD_DIR.exists():
        return []
    out = []
    for d in sorted(UPLOAD_DIR.iterdir(), reverse=True)[:20]:
        info = describe(d.name)
        if info:
            out.append(info)
    return out


def delete_repo(repo_id: str) -> bool:
    if not re.fullmatch(r"r_[0-9]{8}_[0-9]{6}_[0-9a-f]{4}", repo_id):
        return False
    d = UPLOAD_DIR / repo_id
    if d.is_dir():
        shutil.rmtree(d)
        return True
    return False
