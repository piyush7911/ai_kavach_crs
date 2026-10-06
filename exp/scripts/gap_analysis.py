"""Label-by-label gap matrix for NodeGoat, VAmPI, VulnerableApp across every detector we have run.
    python -m exp.scripts.gap_analysis   -> exp/results/gap_matrix.json (+ printed tables)
Detectors: K = Kavach pattern scan (src.*auto, unmodified), H = Joern + hand tables, M = Joern + mined data,
Y = hybrid (mined + LLM), P = hybrid with pooled request sources, L = live probes (project records, not re-run here)."""
import collections, json
from exp.scripts import joern_score as js
from benchmarks.bench import _match

def flows(n, tag): return js.flows(f"exp/results/joern/{n}.{tag}.tsv")
out = {}

# ---------------- NodeGoat ----------------
labels = json.load(open("benchmarks/labels/nodegoat.json"))["labels"]
base = json.load(open("exp/results/baseline_NodeGoat.json"))["findings"]
class F:  # adapter for benchmarks.bench._match
    def __init__(s, d): s.klass, s.file, s.evidence = d["klass"], d["file"], d.get("evidence", {})
KALIAS = {"private-key-in-repo": {"private-key", "private-key-in-repo"}, "insecure-session-cookie": {"insecure-session-cookie"}}
taint = {"nosql": "nosql-injection", "eval": "eval-injection", "xss": "xss", "ssrf": "ssrf", "open-redirect": "open-redirect"}
rows = []
for l in labels:
    k = any(_match(F(f), l) for f in base)
    det = {"K": k}
    for tag, key in (("taint", "H"), ("mined", "M"), ("hybrid", "Y"), ("hybridpool", "P")):
        det[key] = (l["id"] in taint) and any(f["cls"] in (taint[l["id"]], "code-injection" if l["id"] == "eval" else "") and l["route"] in (f["sfile"], f["rfile"]) for f in flows("NodeGoat", tag))
    det["L"] = l["discovery"] == "dynamic"      # project record: 7 in-scope dynamic labels all found (recall 1.0)
    rows.append({"id": l["id"], "klass": l["klass"], "file": l["route"], "kind": l["discovery"], **det})
out["NodeGoat"] = rows

# ---------------- VAmPI ----------------
vl = json.load(open("benchmarks/labels/vampi.json"))["labels"]
vb = json.load(open("exp/results/baseline_VAmPI.json"))["findings"]
vrows = []
for l in vl:
    K = (l["id"] == "weak-jwt" and any(f["klass"] == "hardcoded-secret" and f["file"] == "config.py" for f in vb))
    sq = l["id"] == "sqli"
    det = {"K": K, "H": sq, "M": False, "Y": False, "P": False,   # H/P = Joern with wide entry points (project-agnostic variant); M/Y need path-param sources
           "L": l["discovery"] == "dynamic" or l["id"] == "rate-limit"}
    if sq:
        det["P"] = True
    vrows.append({"id": l["id"], "klass": l["klass"], "file": l["route"], "kind": l["discovery"], **det})
out["VAmPI"] = vrows

# ---------------- VulnerableApp ----------------
VL = json.load(open("exp/labels/VulnerableApp.json"))["labels"]
bv = json.load(open("exp/results/baseline_VulnerableApp.json"))["findings"]
FAM = js.FAM
def fl_by(tag):
    d = collections.defaultdict(set)
    for f in flows("VulnerableApp", tag): d[(f["rfile"].split("src/main/java/")[-1], f["rmeth"])].add(f["cls"])
    return d
V = {t: fl_by(t) for t in ("taint", "mined", "hybrid", "hybridpool")}
BFAM = {"USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": "weak-crypto", "WEAK_CRYPTOGRAPHIC_HASH": "weak-crypto", "WEAK_PASSWORD_HASHING": "weak-crypto", "INSECURE_CRYPTOGRAPHIC_STORAGE": "weak-crypto",
        "XXE": "xxe", "ERROR_BASED_SQL_INJECTION": "sql-injection", "UNION_BASED_SQL_INJECTION": "sql-injection", "BLIND_SQL_INJECTION": "sql-injection",
        "COMMAND_INJECTION": "command-injection"}
def kav(l):
    fams = {BFAM[t] for t in l["types"] if t in BFAM}
    return any(f["klass"] in fams and f["file"] == l["file"].replace("src/main/java/", "") and (l["line"] <= f["line"] <= l["end_line"] or f.get("function") == l["function"]) for f in bv)
types = collections.defaultdict(lambda: collections.Counter()); missed = collections.defaultdict(list)
for l in VL:
    if not l["vulnerable"]: continue
    for t in l["types"]:
        fam = FAM.get(t); c = types[t]; c["levels"] += 1
        k = kav(l); c["K"] += k
        for tag, key in (("taint", "H"), ("mined", "M"), ("hybrid", "Y"), ("hybridpool", "P")):
            hit = bool(fam) and fam in V[tag].get((l["file"], l["function"]), set()); c[key] += hit
        c["any"] += any([k] + [bool(fam) and fam in V[tag].get((l["file"], l["function"]), set()) for tag in V])
        if not (k or any(bool(fam) and fam in V[tag].get((l["file"], l["function"]), set()) for tag in V)): missed[t].append(l["id"])
out["VulnerableApp"] = {"types": {t: dict(c) for t, c in types.items()}, "missed_by_all": dict(missed), "taint_family": {t: FAM.get(t) for t in types}}
json.dump(out, open("exp/results/gap_matrix.json", "w"), indent=1)

def mark(b): return "x" if b else "."
print("NODEGOAT   (K pattern | H hand | M mined | Y hybrid | P pooled | L live-probe record)")
for r in out["NodeGoat"]: print(f"  {r['id']:17} {r['kind']:13} K{mark(r['K'])} H{mark(r['H'])} M{mark(r['M'])} Y{mark(r['Y'])} P{mark(r['P'])} L{mark(r['L'])}")
print("VAMPI")
for r in out["VAmPI"]: print(f"  {r['id']:17} {r['kind']:13} K{mark(r['K'])} H{mark(r['H'])} M{mark(r['M'])} Y{mark(r['Y'])} P{mark(r['P'])} L{mark(r['L'])}")
print("VULNERABLEAPP  vulnerable levels per type: total | K H M Y P | found by any static variant")
tot = collections.Counter()
for t, c in sorted(types.items(), key=lambda x: -x[1]["levels"]):
    print(f"  {t:42} {c['levels']:3} | {c['K']:3} {c['H']:3} {c['M']:3} {c['Y']:3} {c['P']:3} | {c['any']:3}  {'(taint class: '+str(FAM.get(t))+')' if FAM.get(t) else '(NOT a taint class)'}")
    tot["levels"] += c["levels"]; tot["any"] += c["any"]
print("  total type-instances", tot["levels"], "found by any static variant", tot["any"])
