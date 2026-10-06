"""Merge a mined data file with LLM-proposed specs into one hybrid knowledge file.
    python -m exp.scripts.merge_knowledge exp/knowledge/java.json exp/knowledge/llm_VulnerableApp.json exp/knowledge/hybrid_VulnerableApp.json
LLM sources (class "*") apply to every class; sinks/sanitizers are added per class. Specs keep classified_by="llm"."""
import json, sys
mined, llm, out = (json.load(open(sys.argv[i])) for i in (1, 2)) + [None] if False else (None, None, None)
a, b, o = sys.argv[1:4]
mined, llm = json.load(open(a)), json.load(open(b))
classes = set(mined["sinks"]) | set(llm["sinks"]) | set(mined["sources"])
hy = {"_about": "hybrid = community-mined + LLM-proposed gap specs", "sources": {}, "sinks": {}, "sanitizers": {}}
for c in classes | {"sql-injection", "nosql-injection", "command-injection", "code-injection", "xss", "path-traversal", "ssrf", "open-redirect", "xxe",
                    "deserialization", "ssti", "ldap-injection", "xpath-injection"}:
    hy["sources"][c] = mined["sources"].get(c, []) + llm["sources"].get("*", [])
    hy["sinks"][c] = mined["sinks"].get(c, []) + llm["sinks"].get(c, [])
    hy["sanitizers"][c] = mined["sanitizers"].get(c, []) + llm["sanitizers"].get(c, [])
if "--pool" in sys.argv:        # request-input sources (annotated params, typed request objects, request property access) are class-independent
    pool = [x for v in mined["sources"].values() for x in v if x["kind"] in ("param", "typed", "access") and x.get("recv") not in ("event",)]
    seen, uniq = set(), []
    for x in pool:
        k = json.dumps({a: b for a, b in x.items() if a not in ("rule", "fw")}, sort_keys=True)
        if k not in seen: seen.add(k); uniq.append(x)
    for c in hy["sources"]: hy["sources"][c] = uniq + llm["sources"].get("*", [])
    hy["_about"] += " (request-input sources pooled across classes)"
json.dump(hy, open(o, "w"), indent=1)
print(o, {k: sum(len(v) for v in hy[k].values()) for k in ("sources", "sinks", "sanitizers")})
