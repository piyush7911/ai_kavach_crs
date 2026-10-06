import json, re, sys, time, dataclasses
from pathlib import Path
sys.path.insert(0, ".")
from src.pyauto import static as pys
from src.javaauto import static as jvs
from exp.scripts import score_app, score_owasp_java

SR = Path("exp/third_party/semgrep-rules")
CWE = {89:"sql",564:"sql",78:"command",77:"command",94:"code",95:"code",22:"path",23:"path",36:"path",918:"ssrf",79:"xss",80:"xss",
       611:"xxe",827:"xxe",502:"deserialization",601:"redirect",798:"secret",321:"secret",259:"secret",489:"misconfig",215:"misconfig",
       352:"csrf",639:"idor",284:"authz",285:"authz",862:"authz",863:"authz",1336:"ssti",327:"crypto",328:"crypto",916:"crypto",
       347:"jwt",345:"jwt",1004:"misconfig",614:"misconfig",1275:"misconfig",732:"misconfig"}
def fam(f):
    cw = f.cwe if isinstance(f.cwe, str) else " ".join(f.cwe or [])
    for n in re.findall(r"CWE-(\d+)", cw):
        if int(n) in CWE: return CWE[int(n)]
    r = f.rule.lower()
    for k, v in [("pickle","deserialization"),("yaml","deserialization"),("csrf","csrf"),("autoescape","xss"),("safe","xss"),
                 ("debug","misconfig"),("ssrf","ssrf"),("xxe","xxe"),("ssti","ssti"),("render-template-string","ssti"),("raw","sql"),("sqli","sql"),("md5","crypto"),("hasher","crypto")]:
        if k in r: return v
    return "other:" + f.rule
def run(scanner, target, rules):
    t=time.time(); fs = scanner(target, rules); return fs, round(time.time()-t,1)

def score_labels(tname, fs):
    d=[{"klass":fam(f),"file":f.file,"line":f.line,"function":f.function} for f in fs]
    p=Path(f"/tmp_{tname}.json")
    out=Path(f"{S_OUT}/{tname}.json"); out.write_text(json.dumps({"findings":d}))
    labels,hit,unl,_=score_app.score(tname,str(out)); return labels,hit,unl,d

S_OUT = sys.argv[1]
APPS = ["DVFA","breakableflask","django.nv","vulnerable-django-app"]
res={}
for a in APPS:
    tgt=f"benchmark_workspace/public/{a}"
    base,_=run(pys.scan,tgt,pys.RULES)
    comm,secs=run(pys.scan,tgt,SR/"python")
    labels,hit_c,unl,d=score_labels(a,comm)
    _,hit_b,_,_=score_labels(a,base)
    # base uses scanner klass names -> rescore through family map for fairness
    import collections
    print(f"\n## {a}: true {len(labels)} | baseline found {len(hit_b)} | community found {len(hit_c)} | union {len(hit_b|hit_c)} | community findings {len(comm)} (unlabeled {len(unl)}) {secs}s")
    print("   community FOUND:", ", ".join(sorted(hit_c)) or "-")
    print("   still MISSED   :", ", ".join(l["id"] for l in labels if l["id"] not in (hit_b|hit_c)) or "-")
    print("   unlabeled top :", collections.Counter(x["klass"] for x in unl).most_common(6))
    res[a]={"true":len(labels),"base":sorted(hit_b),"community":sorted(hit_c),"findings":len(comm),"unlabeled":len(unl),"secs":secs}
json.dump(res,open(f"{S_OUT}/py_summary.json","w"),indent=1)
