"""OpenSSF CVE Benchmark runner: fetch each CVE's pre-patch (and post-patch) commit, scan with Kavach's JS scanner,
check whether a finding lands on the documented weakness (same file, within WINDOW lines), and whether the same
finding disappears on the post-patch commit.
    python -m benchmarks.public.ossf_run [--limit N] [--workers 3]
Output: reports/public_bench/ossf/<CVE>.json and summary.json"""
import argparse, json, subprocess, sys, shutil, os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CVES = Path("benchmark_workspace/public/ossf-cve-benchmark/CVEs")
WORK = Path("benchmark_workspace/public/ossf_checkouts"); OUT = Path("reports/public_bench/ossf")
WINDOW = 5
PY = sys.executable

def sh(cmd, cwd=None, timeout=300):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})

def checkout(repo, commit, dest):
    if (dest / ".kavach_ok").exists(): return True
    shutil.rmtree(dest, ignore_errors=True); dest.mkdir(parents=True)
    if sh(["git", "init", "-q"], dest).returncode: return False
    sh(["git", "remote", "add", "origin", repo], dest)
    r = sh(["git", "fetch", "-q", "--depth", "1", "origin", commit], dest)
    if r.returncode: return False
    if sh(["git", "checkout", "-q", "FETCH_HEAD"], dest).returncode: return False
    shutil.rmtree(dest / ".git", ignore_errors=True); (dest / ".kavach_ok").write_text("1"); return True

def scan(path, out):
    r = sh([PY, "-m", "src.jsauto", "--target", str(path), "--out", str(out), "--no-deps"], timeout=600)
    if not out.exists(): return None
    return json.load(open(out))["findings"]

def hits(findings, w):
    w = w.get("location", w)
    """findings on the weakness' file within WINDOW lines (or the same enclosing function span)."""
    res = []
    for f in findings or []:
        if f["file"] != w["file"]: continue
        line = f.get("line") or 0; fl = (f.get("evidence") or {}).get("function_lines")
        if abs(line - w["line"]) <= WINDOW or (fl and fl[0] <= w["line"] <= fl[1]): res.append(f)
    return res

def one(cve_file):
    d = json.load(open(cve_file)); cve = d["CVE"]; out = OUT / f"{cve}.json"
    if out.exists(): return json.load(open(out))
    rec = {"cve": cve, "cwes": d["CWEs"], "repo": d["repository"], "weaknesses": d["prePatch"]["weaknesses"]}
    try:
        pre = WORK / cve / "pre"; post = WORK / cve / "post"
        if not checkout(d["repository"], d["prePatch"]["commit"], pre): rec["status"] = "checkout-failed"
        else:
            if not (pre / "package.json").exists(): (pre / "package.json").write_text('{"name":"x"}')
            pf = scan(pre, OUT / f"{cve}.pre.findings.json")
            if pf is None: rec["status"] = "scan-failed"
            else:
                rec["status"] = "ok"; rec["findings_pre"] = len(pf)
                rec["detected"] = [bool(hits(pf, w)) for w in d["prePatch"]["weaknesses"]]
                rec["hit_classes"] = sorted({f["klass"] for w in d["prePatch"]["weaknesses"] for f in hits(pf, w)})
                if checkout(d["repository"], d["postPatch"]["commit"], post):
                    if not (post / "package.json").exists(): (post / "package.json").write_text('{"name":"x"}')
                    qf = scan(post, OUT / f"{cve}.post.findings.json")
                    if qf is not None:
                        rec["findings_post"] = len(qf)
                        rec["cleared_after_patch"] = [bool(hits(pf, w)) and not bool(hits(qf, w)) for w in d["prePatch"]["weaknesses"]]
    except Exception as e: rec["status"] = f"error: {e}"[:200]
    json.dump(rec, open(out, "w"), indent=1); return rec

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--limit", type=int, default=0); ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args(); OUT.mkdir(parents=True, exist_ok=True); WORK.mkdir(parents=True, exist_ok=True)
    files = sorted(CVES.glob("*.json")); files = files[:a.limit] if a.limit else files
    with ThreadPoolExecutor(a.workers) as ex: recs = list(ex.map(one, files))
    ok = [r for r in recs if r["status"] == "ok"]
    tw = sum(len(r["weaknesses"]) for r in ok); dw = sum(sum(r["detected"]) for r in ok)
    s = {"cves": len(recs), "scanned": len(ok), "checkout_failed": sum(r["status"] == "checkout-failed" for r in recs),
         "scan_failed": sum(r["status"] == "scan-failed" for r in recs), "weaknesses": tw, "detected": dw,
         "cve_detected": sum(any(r["detected"]) for r in ok),
         "cleared_after_patch": sum(sum(r.get("cleared_after_patch", [])) for r in ok)}
    json.dump(s, open(OUT / "summary.json", "w"), indent=1); print(s)
