"""
Mutate a Node app so that nothing in it matches the names the detector was developed against.

If detection depends on a name (a parameter called `req`, a file called `contributions.js`, a
function called `handleContributionsUpdate`) it breaks here. Same program, different spelling.
"""
import re
import shutil
from pathlib import Path


def mutate(src: Path, dst: Path) -> dict:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "node_modules"))
    renamed_files = {}
    # 1. rename the HTTP request/response parameters everywhere they are used as identifiers
    for js in list(dst.rglob("*.js")):
        if "vendor" in js.parts or "assets" in js.parts:
            continue
        text = js.read_text(errors="replace")
        text = re.sub(r"\breq\b", "incomingMsg", text)
        text = re.sub(r"\bres\b", "outgoingMsg", text)
        js.write_text(text)
    # 2. rename source files and handler functions: nothing may rely on the original names
    for js in list(dst.rglob("*.js")):
        if "vendor" in js.parts or "assets" in js.parts or js.name in ("server.js",):
            continue
        new = js.with_name("m_" + js.name)
        js.rename(new)
        renamed_files[js.name] = new.name
    for js in list(dst.rglob("*.js")):
        t = js.read_text(errors="replace")
        for old, new in renamed_files.items():
            t = t.replace(f'/{old[:-3]}"', f'/m_{old[:-3]}"').replace(f"/{old[:-3]}'", f"/m_{old[:-3]}'")
        for fn in ("handleContributionsUpdate", "displayResearch", "searchCriteria", "handleProfileUpdate"):
            t = t.replace(fn, "zz_" + fn[::-1])
        js.write_text(t)
    return renamed_files
