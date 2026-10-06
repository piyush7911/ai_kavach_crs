"""Score a Kavach Java findings.json against OWASP BenchmarkJava expectedresults-1.2.csv.
Standard OWASP Benchmark scoring: per category TPR (recall on real vulns), FPR (flagged safe tests), Youden = TPR-FPR.
    python -m benchmarks.public.score_owasp_java findings.json expectedresults.csv [--out score.json]"""
import csv, json, re, sys, collections

KLASS2CAT = {"sql-injection": "sqli", "command-injection": "cmdi", "path-traversal": "pathtraver", "xss": "xss",
             "weak-crypto": "crypto", "weak-hash": "hash", "ldap-injection": "ldapi", "insecure-cookie": "securecookie",
             "trust-boundary": "trustbound", "weak-random": "weakrand", "xpath-injection": "xpathi"}

def score(findings_path, csv_path):
    truth = {}
    for row in csv.reader(open(csv_path)):
        if not row or row[0].startswith("#"): continue
        truth[row[0]] = (row[1], row[2] == "true")
    flagged = collections.defaultdict(set)
    for f in json.load(open(findings_path))["findings"]:
        m = re.search(r"(BenchmarkTest\d+)", f["file"])
        cat = KLASS2CAT.get(f["klass"])
        if m and cat: flagged[m.group(1)].add(cat)
    res, tot = {}, collections.Counter()
    for t, (cat, real) in truth.items():
        r = res.setdefault(cat, collections.defaultdict(int))
        hit = cat in flagged.get(t, ())
        r["real" if real else "safe"] += 1
        if real and hit: r["tp"] += 1
        if real and not hit: r["fn"] += 1
        if not real and hit: r["fp"] += 1
        if not real and not hit: r["tn"] += 1
    out = {}
    for cat, r in sorted(res.items()):
        tpr = r["tp"] / r["real"]; fpr = r["fp"] / r["safe"]
        r = {k: r[k] for k in ("real","safe","tp","fn","fp","tn")}
        out[cat] = {**r, "tpr": round(tpr, 3), "fpr": round(fpr, 3), "youden": round(tpr - fpr, 3)}
        tot.update(r)
    tpr = tot["tp"] / tot["real"]; fpr = tot["fp"] / tot["safe"]
    out["OVERALL"] = {**tot, "tpr": round(tpr, 3), "fpr": round(fpr, 3), "youden": round(tpr - fpr, 3)}
    return out

if __name__ == "__main__":
    s = score(sys.argv[1], sys.argv[2])
    print(f"{'cat':14}{'real':>6}{'tp':>6}{'fn':>6}{'safe':>6}{'fp':>6}{'TPR':>7}{'FPR':>7}{'Youden':>8}")
    for c, r in s.items():
        print(f"{c:14}{r['real']:>6}{r['tp']:>6}{r['fn']:>6}{r['safe']:>6}{r['fp']:>6}{r['tpr']:>7}{r['fpr']:>7}{r['youden']:>8}")
    if "--out" in sys.argv: json.dump(s, open(sys.argv[sys.argv.index("--out") + 1], "w"), indent=1)
