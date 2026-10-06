"""Score the new pipeline on OWASP BenchmarkJava (held-out). Standard OWASP scoring: per category TPR (real vulns found), FPR (safe tests flagged), Youden = TPR - FPR.
    python -m exp.scripts.bj_score [taint.tsv] [misuse.tsv]
Variants: K Kavach pattern scan | C community Semgrep java rules | T taint (steps 1-4) | M misuse catalogue (step 3) | N = T or M (new pipeline) | N+C | N+K+C."""
import collections, csv, json, re, sys
from exp.scripts import joern_score as js
from exp.scripts.score_owasp_java import KLASS2CAT

CSV = "benchmark_workspace/public/BenchmarkJava/expectedresults-1.2.csv"
CAT_OF_CLASS = {"sql-injection": "sqli", "command-injection": "cmdi", "path-traversal": "pathtraver", "xss": "xss", "ldap-injection": "ldapi", "xpath-injection": "xpathi",
                "weak-hash": "hash", "weak-cipher": "crypto", "weak-random": "weakrand", "cookie-flags": "securecookie"}
TEST = re.compile(r"(BenchmarkTest\d+)")
def test_of(*files):
    for f in files:
        m = TEST.search(f or "")
        if m: return m.group(1)
    return None

def truth():
    t = {}
    for row in csv.reader(open(CSV)):
        if row and not row[0].startswith("#"): t[row[0]] = (row[1], row[2] == "true")
    return t

def taint_flags(path):
    out = collections.defaultdict(set)
    for f in js.flows(path):
        cat = CAT_OF_CLASS.get(f["cls"]); t = test_of(f["rfile"], f["sfile"])
        if cat and t: out[t].add(cat)
    return out
def misuse_flags(path):
    out = collections.defaultdict(set)
    for r in csv.reader(open(path), delimiter="\t"):
        if r and r[0] in ("HIT", "VIA"):
            cat = CAT_OF_CLASS.get(r[1]); t = test_of(r[2])
            if cat and t: out[t].add(cat)
    return out
def finding_flags(path):
    out = collections.defaultdict(set)
    for f in json.load(open(path))["findings"]:
        cat = KLASS2CAT.get(f["klass"]); t = test_of(f["file"])
        if cat and t: out[t].add(cat)
    return out
def union(*ds):
    out = collections.defaultdict(set)
    for d in ds:
        for k, v in d.items(): out[k] |= v
    return out

def score(flags, T):
    res = collections.defaultdict(lambda: collections.Counter())
    for t, (cat, real) in T.items():
        hit = cat in flags.get(t, ())
        r = res[cat]; r["real" if real else "safe"] += 1
        if real and hit: r["tp"] += 1
        if not real and hit: r["fp"] += 1
    tot = collections.Counter()
    for r in res.values(): tot.update(r)
    return res, tot

def fmt(res, tot):
    rows = {}
    for c, r in sorted(res.items()):
        tpr = r["tp"] / r["real"]; fpr = r["fp"] / r["safe"]; rows[c] = (r["real"], r["tp"], r["safe"], r["fp"], round(tpr, 3), round(fpr, 3), round(tpr - fpr, 3))
    tpr = tot["tp"] / tot["real"]; fpr = tot["fp"] / tot["safe"]; rows["OVERALL"] = (tot["real"], tot["tp"], tot["safe"], tot["fp"], round(tpr, 3), round(fpr, 3), round(tpr - fpr, 3))
    return rows

if __name__ == "__main__":
    taint = sys.argv[1] if len(sys.argv) > 1 else "exp/results/joern/BenchmarkJava.final4.tsv"
    mis = sys.argv[2] if len(sys.argv) > 2 else "exp/results/joern/BenchmarkJava.misuse.tsv"
    T = truth(); K = finding_flags("exp/results/BenchmarkJava.findings.json"); C = finding_flags("exp/results/community/BenchmarkJava.community.json")
    TT = taint_flags(taint); M = misuse_flags(mis); N = union(TT, M)
    variants = {"K Kavach pattern scan": K, "C community Semgrep rules": C, "T taint (steps 1-4)": TT, "M misuse catalogue (step 3)": M, "N = T+M (new pipeline)": N,
                "N + C": union(N, C), "N + K + C": union(N, K, C)}
    allrows = {}
    for name, fl in variants.items(): allrows[name] = fmt(*score(fl, T))
    json.dump(allrows, open("exp/results/bj_final.json", "w"), indent=1)
    print(f"{'variant':32}{'TPR':>7}{'FPR':>7}{'TPR-FPR':>9}   (real {allrows['T taint (steps 1-4)']['OVERALL'][0]}, safe {allrows['T taint (steps 1-4)']['OVERALL'][2]})")
    for n, r in allrows.items(): o = r["OVERALL"]; print(f"{n:32}{o[4]:>7}{o[5]:>7}{o[6]:>9}")
    print("\nper category (new pipeline N):  real  tp  safe  fp   TPR   FPR  TPR-FPR")
    for c, o in allrows["N = T+M (new pipeline)"].items(): print(f"  {c:14}{o[0]:>6}{o[1]:>5}{o[2]:>6}{o[3]:>5}{o[4]:>7}{o[5]:>6}{o[6]:>8}")
