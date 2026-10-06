"""Score Kavach findings against a hand-built answer key (exp/labels/<target>.json).
A finding matches a label when: same family, same file, and (enclosing function in label.functions OR line inside label.lines).
Findings matching no label are listed as UNLABELED (candidate false positives, to be triaged by hand).
    python -m exp.scripts.score_app <target> <findings.json>"""
import json, sys

FAMILY = {  # scanner klass -> family
 "sql-injection": "sql", "tainted-sql-string": "sql", "express-sequelize-injection": "sql", "nosql-injection": "sql",
 "command-injection": "command", "code-injection": "code", "eval-injection": "code", "path-traversal": "path",
 "express-res-sendfile": "path", "ssrf": "ssrf", "xss": "xss", "xxe": "xxe", "express-libxml-noent": "xxe",
 "deserialization": "deserialization", "express-third-party-object-deserialization": "deserialization",
 "open-redirect": "redirect", "idor": "idor", "hardcoded-secret": "secret", "hardcoded-jwt-secret": "secret",
 "express-session-hardcoded-secret": "secret", "debug-enabled": "misconfig", "csrf-missing": "csrf", "csrf": "csrf",
 "broken-access-control": "authz", "authz": "authz", "ssti": "ssti", "template-injection": "ssti", "weak-crypto": "crypto",
 "weak-hash": "crypto", "jwt": "jwt", "weak-jwt": "jwt", "insecure-session-cookie": "misconfig", "express-check-directory-listing": "misconfig"}

def matches(f, l):
    fam = FAMILY.get(f["klass"], f["klass"])
    if fam != l["family"] or f["file"] != l["file"]: return False
    if f.get("function") in l.get("functions", []): return True
    a, b = l.get("lines", [0, -1]); return a <= (f.get("line") or 0) <= b

def score(target, findings_path):
    labels = json.load(open(f"exp/labels/{target}.json"))["labels"]
    fs = json.load(open(findings_path))["findings"]
    hit = {l["id"] for l in labels for f in fs if matches(f, l)}
    unl = [f for f in fs if not any(matches(f, l) for l in labels)]
    return labels, hit, unl, fs

if __name__ == "__main__":
    t = sys.argv[1]; labels, hit, unl, fs = score(t, sys.argv[2])
    print(f"{t}: true bugs {len(labels)} | findings {len(fs)} | true bugs found {len(hit)} ({100*len(hit)//len(labels)}% recall)")
    print("  MISSED:", ", ".join(l["id"] for l in labels if l["id"] not in hit) or "-")
    print(f"  UNLABELED findings ({len(unl)}):")
    for f in unl: print(f"    {f['klass']:28} {f['file']}:{f.get('line')} ({f.get('function')})")
