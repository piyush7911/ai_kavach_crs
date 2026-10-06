"""Candidate sanity pruner, adapted from Shannon's review constraints #12/#13 (AGPL — ideas only).

Cheap, deterministic checks on a STATIC candidate (from Joern/Opengrep/vocab) before it is even reported in
the candidate tier — catches the two failure modes a source-reading finder hits:
  #12 anti-hallucination: the cited file must exist and the line be within range; if a function is named it
      must actually appear in the file. A candidate pointing at a nonexistent location is dropped.
  #13 trust-boundary: an INJECTION-class candidate must cite an ingress — a tainted parameter/source — or it
      is not a reachable-input finding. Missing ingress → demote (keep as low-signal), not drop.
Confirmed findings (an oracle already fired) are exempt: the exploit is the proof, the location is secondary.
"""
from __future__ import annotations

import re
from pathlib import Path

_TAINT_CLASSES = {"sql-injection", "nosql-injection", "command-injection", "path-traversal", "ssrf",
                  "xss", "xxe", "insecure-deserialization", "ssti", "open-redirect", "code-injection",
                  "ldap-injection"}


def sanity(finding: dict, source_root: str) -> tuple[str, str]:
    """Return (verdict, reason). verdict ∈ {ok, drop, demote}. `drop` = hallucinated location (#12);
    `demote` = no ingress for an injection class (#13); `ok` = passes. Confirmed findings always ok."""
    if finding.get("status") == "confirmed":
        return "ok", "confirmed by oracle — location is secondary to the exploit"
    rel = finding.get("file", "")
    if not rel or rel == "(runtime)":
        return "ok", "runtime/route finding — no source location to verify"
    root = Path(source_root)
    hits = list(root.rglob(Path(rel).name))
    if not hits:
        return "drop", f"#12 cited file {rel!r} does not exist in the tree (hallucinated location)"
    text = hits[0].read_text(errors="replace")
    lines = text.splitlines()
    line = int(finding.get("line") or 0)
    if line and line > len(lines) + 1:
        return "drop", f"#12 cited line {line} is past EOF ({len(lines)} lines)"
    fn = finding.get("function", "")
    if fn and not re.search(rf"\b{re.escape(fn)}\b", text):
        return "drop", f"#12 cited function {fn!r} does not appear in {rel}"
    # #13 trust-boundary: an injection candidate needs an ingress (a tainted param / source)
    if finding.get("klass") in _TAINT_CLASSES:
        ev = finding.get("evidence") or {}
        has_ingress = bool(ev.get("param") or ev.get("reason") or ev.get("sink") or ev.get("lines"))
        if not has_ingress:
            return "demote", "#13 no ingress (tainted param/source) cited — low-signal candidate"
    return "ok", "location verified"


def prune(findings: list[dict], source_root: str) -> dict:
    """Apply sanity() to a candidate list; return {kept, dropped, demoted} counts + annotate each finding
    with evidence['sanity']. Dropped findings are returned for audit, not silently discarded."""
    kept = dropped = demoted = 0
    audit = []
    for f in findings:
        verdict, reason = sanity(f, source_root)
        f.setdefault("evidence", {})["sanity"] = f"{verdict}: {reason}"
        if verdict == "drop":
            dropped += 1
            audit.append({"file": f.get("file"), "klass": f.get("klass"), "reason": reason})
        elif verdict == "demote":
            demoted += 1
            f["confidence"] = "low"
        else:
            kept += 1
    return {"kept": kept, "dropped": dropped, "demoted": demoted, "dropped_audit": audit}


def _self_check():
    import tempfile
    d = tempfile.mkdtemp()
    Path(d, "Real.java").write_text("class Real {\n  void handler(){ q.execute(x); }\n}\n")
    # real location + ingress -> ok
    ok = sanity({"status": "candidate", "klass": "sql-injection", "file": "Real.java", "line": 2,
                 "function": "handler", "evidence": {"param": "x"}}, d)
    assert ok[0] == "ok", ok
    # nonexistent file -> drop (#12)
    dr = sanity({"status": "candidate", "klass": "xss", "file": "Ghost.java", "line": 1}, d)
    assert dr[0] == "drop", dr
    # function not in file -> drop (#12)
    dr2 = sanity({"status": "candidate", "klass": "sql-injection", "file": "Real.java", "function": "nope",
                  "evidence": {"param": "x"}}, d)
    assert dr2[0] == "drop", dr2
    # injection with no ingress -> demote (#13)
    de = sanity({"status": "candidate", "klass": "command-injection", "file": "Real.java", "line": 2,
                 "function": "handler", "evidence": {}}, d)
    assert de[0] == "demote", de
    # confirmed -> always ok
    assert sanity({"status": "confirmed", "klass": "xss", "file": "Ghost.java"}, d)[0] == "ok"
    print("candidate_sanity self-check: OK")


if __name__ == "__main__":
    _self_check()
