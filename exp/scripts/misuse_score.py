"""Score step-3 misuse rows (exp/results/joern/<T>.misuse.tsv) at level / label granularity.
    python -m exp.scripts.misuse_score"""
import collections, csv, json
T2C = {"WEAK_PASSWORD_HASHING": "weak-hash", "WEAK_CRYPTOGRAPHIC_HASH": "weak-hash", "PLAINTEXT_PASSWORD_STORAGE": None,
       "USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": "weak-cipher", "INSECURE_CRYPTOGRAPHIC_STORAGE": "weak-cipher",
       "WEAK_RANDOM_NUMBER_GENERATION": "weak-random", "PREDICTABLE_PASSWORD_RESET_TOKEN": "weak-random", "PREDICTABLE_SESSION_ID": "weak-random", "OBSCURED_PREDICTABLE_SESSION_ID": "weak-random",
       "CLIENT_SIDE_VULNERABLE_JWT": "jwt", "SERVER_SIDE_VULNERABLE_JWT": "jwt", "INSECURE_CONFIGURATION_JWT": "jwt",
       "CLICKJACKING": "header-misconfig"}
JWT = {"jwt-none", "jwt-unverified", "jwt-hardcoded-key"}
def rows(path):
    return [r for r in csv.reader(open(path), delimiter="\t") if r and r[0] in ("HIT", "VIA")]

def vulnerableapp():
    R = rows("exp/results/joern/VulnerableApp.misuse.tsv"); L = json.load(open("exp/labels/VulnerableApp.json"))["labels"]
    strip = lambda f: f.split("src/main/java/")[-1]
    flagged = collections.defaultdict(set)         # (file, function) -> classes (via call-graph tags)
    hits = collections.defaultdict(list)           # file -> [(line, class)]
    for r in R:
        cls = "jwt" if r[1] in JWT else r[1]
        if r[0] == "VIA": flagged[(strip(r[2]), r[4])].add(cls)
        else: hits[strip(r[2])].append((int(r[3]), cls))
    by = collections.defaultdict(collections.Counter); found, missed, fps = [], [], []
    for l in L:
        if not (l["vulnerable"] or l["secure"]): continue
        cls = {T2C[t] for t in l["types"] if T2C.get(t)}
        if not cls: continue
        got = set(flagged.get((l["file"], l["function"]), set())) | {c for ln, c in hits.get(l["file"], []) if l["line"] <= ln <= l["end_line"]}
        hit = bool(cls & got); k = sorted(cls)[0]
        if l["vulnerable"]: by[k]["tp" if hit else "fn"] += 1; (found if hit else missed).append(l["id"])
        else: by[k]["fp" if hit else "tn"] += 1; fps += [l["id"]] if hit else []
    tp = sum(v["tp"] for v in by.values()); fn = sum(v["fn"] for v in by.values()); fp = sum(v["fp"] for v in by.values()); tn = sum(v["tn"] for v in by.values())
    return {"in_scope_vulnerable": tp + fn, "found": tp, "secure_in_scope": fp + tn, "secure_flagged": fp, "by_class": {k: dict(v) for k, v in by.items()},
            "found_ids": found, "missed_ids": missed, "flagged_secure_ids": fps}

if __name__ == "__main__":
    r = vulnerableapp(); json.dump(r, open("exp/results/joern/VulnerableApp.misuse.score.json", "w"), indent=1)
    print({k: r[k] for k in ("in_scope_vulnerable", "found", "secure_in_scope", "secure_flagged")}); print("by class", r["by_class"])
    print("missed:", r["missed_ids"]); print("secure flagged:", r["flagged_secure_ids"])
    for t in ("NodeGoat", "VAmPI"):
        print("==", t, "misuse HIT rows"); [print("  ", x[1], x[2], x[3], x[4], x[5]) for x in rows(f"exp/results/joern/{t}.misuse.tsv") if x[0] == "HIT"]
