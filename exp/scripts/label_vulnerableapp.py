"""Ground truth for SasanLabs/VulnerableApp, from the author's own annotations: vulnerable = @AttackVector and not variant=Variant.SECURE; secure = variant=Variant.SECURE.
Every level method carries @VulnerableAppRequestMapping. If it also carries @AttackVector(vulnerabilityExposed=X) it is a
vulnerable level (X is the class); otherwise it is a secure level. Output: exp/labels/VulnerableApp.json"""
import json, re, sys
from pathlib import Path
import tree_sitter_java
from tree_sitter import Language, Parser
P = Parser(Language(tree_sitter_java.language()))
ROOT = Path("benchmark_workspace/public/VulnerableApp/src/main/java")
labels = []
for f in sorted(ROOT.rglob("*.java")):
    src = f.read_bytes(); stack = [P.parse(src).root_node]
    while stack:
        n = stack.pop(); stack.extend(n.children)
        if n.type != "method_declaration": continue
        text = src[n.start_byte:n.end_byte].decode()
        mods = [c for c in n.children if c.type == "modifiers"]
        head = src[mods[0].start_byte:mods[0].end_byte].decode() if mods else ""
        if "@VulnerableAppRequestMapping" not in head: continue
        name = src[n.child_by_field_name("name").start_byte:n.child_by_field_name("name").end_byte].decode()
        types = sorted(set(re.findall(r"VulnerabilityType\.([A-Z_0-9]+)", head)))
        labels.append({"id": f"{f.stem}.{name}", "file": str(f.relative_to(ROOT)), "function": name,
                       "vulnerable": bool(types) and "Variant.SECURE" not in head, "secure": "Variant.SECURE" in head, "types": types, "line": n.start_point[0] + 1, "end_line": n.end_point[0] + 1})
json.dump({"target": "VulnerableApp", "source": "author annotations (@AttackVector = vulnerable level)", "labels": labels},
          open("exp/labels/VulnerableApp.json", "w"), indent=1)
v = [l for l in labels if l["vulnerable"]]
print(len(labels), "level methods;", len(v), "vulnerable;", sum(l["secure"] for l in labels), "secure;", sum(not l["vulnerable"] and not l["secure"] for l in labels), "unmarked (ignored)")
import collections; print(collections.Counter(t for l in v for t in l["types"]).most_common())
