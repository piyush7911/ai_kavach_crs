"""Score Joern taint flows (exp/results/joern/<T>.taint.tsv) against answer keys.
    python -m exp.scripts.joern_score NodeGoat|VAmPI|VulnerableApp [tsv]
Labels outside taint analysis (logic bugs, crypto, config...) are reported as OUT-OF-SCOPE, not as misses."""
import collections, csv, json, sys

def flows(path):
    out = []
    for r in csv.reader(open(path), delimiter="\t"):
        if r and r[0] == "FLOW":
            out.append(dict(cls=r[1], sfile=r[2], sline=r[3], smeth=r[4], rfile=r[5], rline=r[6], rmeth=r[7]))  # s=sink, r=source
    return out

def nodegoat(fl):
    labels = json.load(open("benchmarks/labels/nodegoat.json"))["labels"]
    taint = {"nosql": "nosql-injection", "eval": "eval-injection", "xss": "xss", "ssrf": "ssrf", "open-redirect": "open-redirect"}
    found, scope = [], []
    for l in labels:
        if l["id"] in taint:
            scope.append(l)
            if any(f["cls"] in (taint[l["id"]], "code-injection" if l["id"] == "eval" else "") and l["route"] == f["sfile"] for f in fl): found.append(l["id"])
    matched = [f for f in fl if any(f["cls"] in (taint[l["id"]], "code-injection" if l["id"] == "eval" else "") and l["route"] == f["sfile"] for l in scope)]
    return dict(true_total=len(labels), in_scope=[l["id"] for l in scope], found=found,
                missed=[l["id"] for l in scope if l["id"] not in found], out_of_scope=[l["id"] for l in labels if l["id"] not in taint],
                flows=len(fl), flows_unmatched=len(fl) - len(matched), unmatched=[(f["cls"], f["sfile"], f["sline"], f["smeth"]) for f in fl if f not in matched])

def vampi(fl):
    labels = json.load(open("benchmarks/labels/vampi.json"))["labels"]
    hit = any(f["cls"] == "sql-injection" and "users.py" in f["rfile"] and f["rmeth"] == "get_by_username" for f in fl)
    return dict(true_total=len(labels), in_scope=["sqli"], found=["sqli"] if hit else [], missed=[] if hit else ["sqli"],
                out_of_scope=[l["id"] for l in labels if l["id"] != "sqli"], flows=len(fl),
                unmatched=[(f["cls"], f["sfile"], f["sline"], f["smeth"]) for f in fl if not (f["cls"] == "sql-injection" and f["rmeth"] == "get_by_username")])

FAM = {"REFLECTED_XSS": "xss", "PERSISTENT_XSS": "xss", "XXE": "xxe", "LDAP_INJECTION": "ldap-injection", "ERROR_BASED_SQL_INJECTION": "sql-injection",
       "UNION_BASED_SQL_INJECTION": "sql-injection", "BLIND_SQL_INJECTION": "sql-injection", "COMMAND_INJECTION": "command-injection",
       "SIMPLE_SSRF": "ssrf", "PATH_TRAVERSAL": "path-traversal", "OPEN_REDIRECT_3XX_STATUS_CODE": "open-redirect", "INSECURE_DESERIALIZATION": "deserialization", "REMOTE_CODE_EXECUTION": "code-injection"}
def vulnerableapp(fl):
    labels = json.load(open("exp/labels/VulnerableApp.json"))["labels"]
    byfile = collections.defaultdict(set)
    for l in labels:
        for t in l["types"]:
            if t in FAM: byfile[l["file"]].add(FAM[t])
    flagged = collections.defaultdict(set)
    for f in fl:
        flagged[(f["rfile"].split("src/main/java/")[-1], f["rmeth"])].add(f["cls"])
    tp = fn = fp = tn = 0; found, missed, fps = [], [], []; oos = collections.Counter(); by = collections.defaultdict(lambda: collections.Counter())
    for l in labels:
        if not l["vulnerable"] and not l["secure"]: continue
        own = {FAM[t] for t in l["types"] if t in FAM}
        fams = own if (l["vulnerable"] or own) else byfile.get(l["file"], set())
        if not fams:
            oos[("vuln" if l["vulnerable"] else "secure")] += 1; continue
        hit = bool(flagged.get((l["file"], l["function"]), set()) & fams)
        fam = sorted(fams)[0]
        if l["vulnerable"]:
            by[fam]["tp" if hit else "fn"] += 1; (found if hit else missed).append(l["id"]); tp += hit; fn += not hit
        else:
            by[fam]["fp" if hit else "tn"] += 1; fp += hit; tn += not hit
            if hit: fps.append(l["id"])
    return dict(true_total=sum(l["vulnerable"] for l in labels), in_scope_vulnerable=tp + fn, found=tp, missed_n=fn, secure_in_scope=fp + tn,
                secure_flagged=fp, tpr=round(tp / max(tp + fn, 1), 3), fpr=round(fp / max(fp + tn, 1), 3), youden=round(tp / max(tp + fn, 1) - fp / max(fp + tn, 1), 3),
                out_of_scope=dict(oos), by_class={k: dict(v) for k, v in by.items()}, found_ids=found, missed_ids=missed, flagged_secure_ids=fps)

if __name__ == "__main__":
    t = sys.argv[1]; p = sys.argv[2] if len(sys.argv) > 2 else f"exp/results/joern/{t}.taint.tsv"
    r = {"NodeGoat": nodegoat, "VAmPI": vampi, "VulnerableApp": vulnerableapp}[t](flows(p))
    print(json.dumps(r, indent=1)); json.dump(r, open(f"exp/results/joern/{t}.score.json", "w"), indent=1)
