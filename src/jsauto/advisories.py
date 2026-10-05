"""
Offline npm advisory data.

The rules of engagement do not allow reaching the npm registry at the event, so `npm audit` cannot
be used. Instead a snapshot of public vulnerability advisories is built BEFORE the event (this is the
only step that needs the network) and the lockfile is matched against it locally.

    python -m src.jsauto.advisories build --zip osv_npm_all.zip --out config/advisories/npm.json.gz

Source: the OSV.dev npm dump, which mirrors the GitHub Advisory Database. Malware reports (`MAL-*`,
about 97% of the dump) are dropped: they describe malicious packages, not vulnerabilities in code an
application would legitimately depend on. Only fields needed for matching and reporting are kept.

Honest limits: the snapshot is as old as its build date (recorded in `meta`); it knows only packages
with a published advisory; and matching is on the installed version, so it needs a lockfile or an
installed `node_modules`.
"""

import gzip
import hashlib
import json
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Optional

DEFAULT_SNAPSHOT = Path(__file__).resolve().parents[2] / "config" / "advisories" / "npm.json.gz"

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


# -- semver ----------------------------------------------------------------------------------------

def parse_version(v: str) -> Optional[tuple]:
    """A sortable key for a semver string, or None if it is not semver."""
    m = _SEMVER.match((v or "").strip())
    if not m:
        return None
    major, minor, patch = (int(x) if x is not None else 0 for x in m.group(1, 2, 3))
    pre = m.group(4)
    if pre is None:
        return (major, minor, patch, 1, ())                       # a release sorts after its prereleases
    ident = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (major, minor, patch, 0, ident)


def affected(version: str, ranges: list, versions: Optional[list] = None) -> bool:
    """
    Is `version` inside any affected range? `ranges` is OSV's SEMVER event lists:
    [[{"introduced": "0"}, {"fixed": "4.6.5"}], ...]. An explicit `versions` list also counts.
    """
    if versions and version in versions:
        return True
    v = parse_version(version)
    if v is None:
        return False
    for events in ranges:
        lo, active = None, False
        for e in events:
            if "introduced" in e:
                lo = parse_version(e["introduced"]) if e["introduced"] != "0" else (0, 0, 0, 0, ())
                active = lo is not None and v >= lo
            elif "fixed" in e and active:
                fx = parse_version(e["fixed"])
                if fx is not None and v < fx:
                    return True
                active = False
            elif "last_affected" in e and active:
                la = parse_version(e["last_affected"])
                if la is not None and v <= la:
                    return True
                active = False
        if active:                                                 # introduced, never fixed
            return True
    return False


def first_fix(version: str, ranges: list) -> str:
    """The lowest `fixed` version above `version` in the advisory's ranges ('' if none is published)."""
    v = parse_version(version)
    best = None
    for events in ranges:
        for e in events:
            if "fixed" in e:
                fx = parse_version(e["fixed"])
                if fx is not None and v is not None and fx > v and (best is None or fx < best[0]):
                    best = (fx, e["fixed"])
    return best[1] if best else ""


# -- build / load --------------------------------------------------------------------------------------

def build(zip_path: Path, out: Path = DEFAULT_SNAPSHOT) -> dict:
    zip_path, out = Path(zip_path), Path(out)
    packages: dict[str, list] = {}
    kept = skipped = 0
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            if not name.endswith(".json") or name.startswith("MAL-"):
                skipped += 1
                continue
            d = json.loads(z.read(name))
            if d.get("withdrawn"):
                skipped += 1
                continue
            cwe = (d.get("database_specific") or {}).get("cwe_ids") or []
            sev = ((d.get("database_specific") or {}).get("severity") or "").lower()
            for a in d.get("affected", []):
                pkg = a.get("package", {})
                if pkg.get("ecosystem") != "npm":
                    continue
                ranges = [[e for e in r.get("events", [])] for r in a.get("ranges", []) if r.get("type") == "SEMVER"]
                if not ranges and not a.get("versions"):
                    continue
                packages.setdefault(pkg["name"], []).append({
                    "id": d["id"], "aliases": d.get("aliases", [])[:4], "summary": (d.get("summary") or "")[:200],
                    "severity": {"moderate": "medium"}.get(sev, sev or "medium"),
                    "cwe": cwe[0] if cwe else "", "ranges": ranges, "versions": a.get("versions", [])[:200]})
            kept += 1
    meta = {"source": "OSV.dev npm dump (GitHub Advisory Database), malware reports excluded",
            "built": time.strftime("%Y-%m-%d"), "advisories": kept, "skipped_entries": skipped,
            "packages": len(packages), "zip_sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest()}
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt", encoding="utf-8") as fh:
        json.dump({"meta": meta, "packages": packages}, fh, separators=(",", ":"))
    meta["bytes"] = out.stat().st_size
    return meta


def load(path: Path = DEFAULT_SNAPSHOT) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"no advisory snapshot at {path}; build one before the event with "
                                "`python -m src.jsauto.advisories build --zip <osv npm all.zip>`")
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m src.jsauto.advisories")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--zip", required=True)
    b.add_argument("--out", default=str(DEFAULT_SNAPSHOT))
    args = ap.parse_args(argv)
    print(json.dumps(build(Path(args.zip), Path(args.out)), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
