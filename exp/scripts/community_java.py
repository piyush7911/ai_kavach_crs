import json, sys, time, re, collections
sys.path.insert(0, ".")
from pathlib import Path
from src.javaauto import static as jvs
from exp.scripts import score_owasp_java as so
S=sys.argv[1]; SR=Path("exp/third_party/semgrep-rules")
CWE2KLASS={89:"sql-injection",78:"command-injection",22:"path-traversal",23:"path-traversal",36:"path-traversal",79:"xss",
 327:"weak-crypto",326:"weak-crypto",328:"weak-hash",916:"weak-hash",90:"ldap-injection",643:"xpath-injection",614:"insecure-cookie",
 1004:"insecure-cookie",501:"trust-boundary",330:"weak-random",338:"weak-random",
 }
t=time.time(); fs=jvs.scan("benchmark_workspace/public/BenchmarkJava/src/main/java", SR/"java"); secs=round(time.time()-t,1)
out=[]; unmapped=collections.Counter()
for f in fs:
    cw=f.cwe if isinstance(f.cwe,str) else " ".join(f.cwe or [])
    k=None
    for n in re.findall(r"CWE-(\d+)",cw):
        if int(n) in CWE2KLASS: k=CWE2KLASS[int(n)]; break
    if k: out.append({"klass":k,"file":f.file,"line":f.line})
    else: unmapped[f.rule]+=1
json.dump({"findings":out},open(f"{S}/BenchmarkJava.community.json","w"))
print("community findings",len(fs),"mapped",len(out),secs,"s"); print("top unmapped rules",unmapped.most_common(8))
s=so.score(f"{S}/BenchmarkJava.community.json","benchmark_workspace/public/BenchmarkJava/expectedresults-1.2.csv")
print(f"{'cat':14}{'real':>6}{'tp':>6}{'safe':>6}{'fp':>6}{'TPR':>7}{'FPR':>7}{'Youden':>8}")
for c,r in s.items(): print(f"{c:14}{r['real']:>6}{r['tp']:>6}{r['safe']:>6}{r['fp']:>6}{r['tpr']:>7}{r['fpr']:>7}{r['youden']:>8}")
json.dump(s,open(f"{S}/BenchmarkJava.community.score.json","w"),indent=1)
