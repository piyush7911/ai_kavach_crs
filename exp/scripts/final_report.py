"""Combine every step (route map -> taint, framework checks, second-order, misuse catalogue, live checks) and score all three targets.
    python -m exp.scripts.final_report   -> exp/results/final_matrix.json + printed tables
Detector columns: K pattern scan | T0 prior best taint (hybrid pooled) | T taint after steps 1,2,4 | M misuse (step 3) | V live (step 5)."""
import collections, csv, json, re
from exp.scripts import joern_score as js
from exp.scripts.misuse_score import T2C, JWT, rows as misuse_rows
from benchmarks.bench import _match

FAM = js.FAM
T2L = {"CLICKJACKING": {"clickjacking"}, "NO_LOGIN_RATE_LIMITING": {"no-rate-limit"}, "USERNAME_ENUMERATION": {"user-enumeration"},
       "PREDICTABLE_SESSION_ID": {"predictable-session-id"}, "OBSCURED_PREDICTABLE_SESSION_ID": {"predictable-session-id"},
       "CLIENT_SIDE_VULNERABLE_JWT": {"jwt-none-alg", "jwt-weak-secret", "jwt-no-expiry"}, "SERVER_SIDE_VULNERABLE_JWT": {"jwt-none-alg", "jwt-weak-secret", "jwt-no-expiry"},
       "INSECURE_CONFIGURATION_JWT": {"jwt-none-alg", "jwt-weak-secret", "jwt-no-expiry"}, "WEB_CACHE_POISONING": {"host-header-reflection"}, "HEADER_INJECTION": {"header-injection"},
       "REFLECTED_XSS": {"xss-reflected"}, "PERSISTENT_XSS": {"xss-reflected"}, "OPEN_REDIRECT_3XX_STATUS_CODE": {"open-redirect"}}
strip = lambda f: f.split("src/main/java/")[-1]

def taint_flags(tag):
    d = collections.defaultdict(set)
    for f in js.flows(f"exp/results/joern/VulnerableApp.{tag}.tsv"): d[(strip(f["rfile"]), f["rmeth"])].add(f["cls"])
    return d
def misuse_flags():
    d = collections.defaultdict(set); hits = collections.defaultdict(list)
    for r in misuse_rows("exp/results/joern/VulnerableApp.misuse.tsv"):
        cls = "jwt" if r[1] in JWT else r[1]
        if r[0] == "VIA": d[(strip(r[2]), r[4])].add(cls)
        else: hits[strip(r[2])].append((int(r[3]), cls))
    return d, hits
def live_flags():
    d = collections.defaultdict(set)
    for f in json.load(open("exp/results/live/VulnerableApp.live.json"))["findings"]:
        m = re.search(r"\[(.*)::(.*)\]$", f["route"]); d[(m.group(1), m.group(2))].add(f["class"])
    return d

def vulnerableapp():
    L = json.load(open("exp/labels/VulnerableApp.json"))["labels"]
    base = json.load(open("exp/results/baseline_VulnerableApp.json"))["findings"]
    T0, T1 = taint_flags("hybridpool"), taint_flags("final4"); MV, MH = misuse_flags(); LV = live_flags()
    BF = {"USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": "weak-crypto", "WEAK_CRYPTOGRAPHIC_HASH": "weak-crypto", "WEAK_PASSWORD_HASHING": "weak-crypto", "INSECURE_CRYPTOGRAPHIC_STORAGE": "weak-crypto",
          "XXE": "xxe", "ERROR_BASED_SQL_INJECTION": "sql-injection", "UNION_BASED_SQL_INJECTION": "sql-injection", "BLIND_SQL_INJECTION": "sql-injection", "COMMAND_INJECTION": "command-injection"}
    def det(l, t):
        key = (l["file"], l["function"]); r = {}
        fam = FAM.get(t); r["T0"] = bool(fam) and fam in T0.get(key, set()); r["T"] = bool(fam) and fam in T1.get(key, set())
        r["K"] = BF.get(t) is not None and any(f["klass"] == BF[t] and f["file"] == l["file"] and (l["line"] <= f["line"] <= l["end_line"] or f.get("function") == l["function"]) for f in base)
        mc = T2C.get(t); mc = "jwt" if mc == "jwt" else mc
        r["M"] = bool(mc) and (mc in MV.get(key, set()) or any(c == mc and l["line"] <= ln <= l["end_line"] for ln, c in MH.get(l["file"], [])))
        r["V"] = bool(T2L.get(t)) and bool(T2L[t] & LV.get(key, set()))
        return r
    cols = ["K", "T0", "T", "M", "V"]; per = collections.defaultdict(lambda: collections.Counter()); sec = collections.Counter(); seccols = collections.Counter()
    for l in L:
        if not (l["vulnerable"] or l["secure"]): continue
        for t in l["types"]:
            if not (FAM.get(t) or T2C.get(t) or T2L.get(t)): continue
            d = det(l, t); u = any(d[c] for c in ("T", "M", "V"))
            if l["vulnerable"]:
                c = per[t]; c["levels"] += 1
                for k in cols: c[k] += d[k]
                c["union"] += u; c["static_union"] += (d["T"] or d["M"]); c["prior_union"] += (d["K"] or d["T0"]); c["all"] += (u or d["K"])
            else:
                sec["secure_instances"] += 1; sec["flag_union"] += u; sec["flag_static"] += (d["T"] or d["M"]); sec["flag_prior"] += (d["K"] or d["T0"]); sec["flag_all"] += (u or d["K"])
                for k in cols: seccols[k] += d[k]
    tot = collections.Counter()
    for c in per.values(): tot.update(c)
    return {"per_type": {t: dict(c) for t, c in per.items()}, "total": dict(tot), "secure": dict(sec), "secure_by_detector": dict(seccols)}

def labels_app(name):
    LB = json.load(open(f"benchmarks/labels/{name.lower()}.json"))["labels"]; out = []
    base = json.load(open(f"exp/results/baseline_{name}.json"))["findings"]
    class F:
        def __init__(s, d): s.klass, s.file, s.evidence = d["klass"], d["file"], d.get("evidence", {})
    misuse = [r for r in misuse_rows(f"exp/results/joern/{name}.misuse.tsv")]
    live = json.load(open(f"exp/results/live/{name}.live.json"))["findings"]
    liveclasses = {f["class"] for f in live}
    flows = js.flows(f"exp/results/joern/{name}.final4.tsv")
    TL = {"nosql": "nosql-injection", "eval": "eval-injection", "xss": "xss", "ssrf": "ssrf", "open-redirect": "open-redirect", "sqli": "sql-injection"}
    MAPM = {"hardcoded-secret": {"hardcoded-secret"}, "session-cookie": {"insecure-session"}, "csrf": {"csrf-missing"}, "weak-jwt": {"hardcoded-secret"}}
    MAPL = {"csrf": {"csrf-missing"}, "rate-limit": {"no-rate-limit"}, "enumeration": {"user-enumeration"}, "weak-jwt": {"jwt-weak-secret"}, "data-exposure": {"sensitive-data-exposure"},
            "session-cookie": {"cookie-flags"}, "xss": {"xss-reflected"}, "open-redirect": {"open-redirect"}}
    for l in LB:
        i = l["id"]; K = any(_match(F(f), l) for f in base)
        T = i in TL and any(f["cls"] in (TL[i], "code-injection" if i == "eval" else "") and (l["route"] == f["sfile"] or name == "VAmPI") for f in flows)
        if name == "VAmPI" and i == "sqli": T = any(f["cls"] == "sql-injection" and f["rmeth"] == "get_by_username" for f in flows)
        M = i in MAPM and any(r[0] == "HIT" and r[1] in MAPM[i] and (l["route"] in r[2] or l["route"] == "*" or name == "VAmPI" and r[2].endswith("config.py")) for r in misuse)
        V = i in MAPL and bool(MAPL[i] & liveclasses)
        out.append({"id": i, "kind": l["discovery"], "K": K, "T": T, "M": M, "V": V})
    return out

if __name__ == "__main__":
    res = {"VulnerableApp": vulnerableapp(), "NodeGoat": labels_app("NodeGoat"), "VAmPI": labels_app("VAmPI")}
    json.dump(res, open("exp/results/final_matrix.json", "w"), indent=1)
    mk = lambda b: "x" if b else "."
    for n in ("NodeGoat", "VAmPI"):
        print(f"== {n}  K pattern | T taint(steps1,2,4) | M misuse(step3) | V live(step5)")
        for r in res[n]: print(f"  {r['id']:18}{r['kind']:13} K{mk(r['K'])} T{mk(r['T'])} M{mk(r['M'])} V{mk(r['V'])}")
        print("  labels found by K:", sum(r["K"] for r in res[n]), "| by steps 1-5:", sum(r["T"] or r["M"] or r["V"] for r in res[n]), "| by either:", sum(r["K"] or r["T"] or r["M"] or r["V"] for r in res[n]), "of", len(res[n]))
    v = res["VulnerableApp"]; print("== VulnerableApp (vulnerable levels per type)  levels | K T0 T M V | prior(K|T0) static(T|M) all(T|M|V)")
    for t, c in sorted(v["per_type"].items(), key=lambda x: -x[1]["levels"]):
        print(f"  {t:44}{c['levels']:4} | {c.get('K',0):2} {c.get('T0',0):2} {c.get('T',0):2} {c.get('M',0):2} {c.get('V',0):2} | {c.get('prior_union',0):2} {c.get('static_union',0):2} {c.get('union',0):2}")
    print("  TOTAL", v["total"]); print("  secure levels", v["secure"], v["secure_by_detector"])
