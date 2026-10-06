"""LLM-proposed taint specs for library APIs the mined data file does not know (IRIS-style spec inference).

    OPENAI_BASE_URL=... OPENAI_API_KEY=... KAVACH_MODEL=... \
    python -m exp.scripts.llm_spec_infer <candidates.tsv> <lang java|python|javascript> <out.json> [--batch 25] [--workers 4]

The model sees ONLY: a distinct external API (resolved name, or receiver.method) plus one short usage line from the app.
It must answer, per API, a strict JSON verdict: role = source | sink | sanitizer | none, class (for sink/sanitizer), arg index.
Validation: unknown ids, unknown roles/classes and non-integer args are discarded and counted. Every accepted spec is tagged
classified_by="llm" (low confidence). The model decides nothing about what is a bug: the specs only feed the taint engine,
and a flow still has to exist. Every request/response is appended to exp/results/llm_trace.jsonl (the API key is never written).
"""
import argparse, concurrent.futures as cf, csv, json, os, re, sys, time
from pathlib import Path
from openai import OpenAI

CLASSES = ["sql-injection", "nosql-injection", "command-injection", "code-injection", "xss", "path-traversal", "ssrf", "open-redirect",
           "xxe", "deserialization", "ssti", "ldap-injection", "xpath-injection"]
TRACE = Path("exp/results/llm_trace.jsonl")
BORING_PREFIX = ("java.util.", "java.lang.String", "java.lang.Integer", "java.lang.Long", "java.lang.Boolean", "java.lang.Double", "java.lang.Math",
                 "java.lang.Object", "java.lang.Enum", "java.lang.Class", "java.lang.Throwable", "java.lang.Exception", "java.lang.Thread", "java.lang.System",
                 "java.time.", "org.slf4j", "org.apache.logging", "java.lang.Iterable", "java.lang.Character", "__ecma", "__whatwg.console")
BORING_NAMES = {"push", "pop", "shift", "map", "forEach", "filter", "log", "error", "warn", "toString", "length", "keys", "values", "slice", "indexOf",
                "includes", "concat", "join", "split", "trim", "toLowerCase", "toUpperCase", "append", "format", "len", "str", "int", "isinstance", "print", "range"}

SYSTEM = ("You are a static-analysis specialist writing taint specifications for a Joern-style taint engine. For each library API call "
          "listed, decide its role for taint tracking of web-application vulnerabilities.\n"
          "role: 'source' = returns attacker-controlled data (HTTP request input, uploaded file, external response body); "
          "'sink' = dangerous when a tainted value reaches the argument (SQL/NoSQL query text, OS command, code eval, HTML/response output, file path, "
          "outbound URL, redirect target, XML parser input, LDAP/XPath query, deserializer input); "
          "'sanitizer' = neutralises taint for a class (escaping, encoding, parameter binding that makes the value safe, strict validation that returns a safe value); "
          "'none' = anything else (collections, logging, getters, plain utilities).\n"
          f"class (required for sink and sanitizer): one of {CLASSES}.\n"
          "arg: 0-based position of the dangerous (sink) or neutralised (sanitizer) argument, or null if any argument.\n"
          "Be conservative: answer 'none' when unsure. Reply with ONLY a JSON array, one object per input id: "
          '[{"id": 3, "role": "sink", "class": "sql-injection", "arg": 0}, {"id": 4, "role": "none"}]')

def load(tsv, lang):
    seen, out = set(), []
    for r in csv.reader(open(tsv), delimiter="\t"):
        if len(r) < 5: continue
        name, recv, mfn, ex, cnt = r[0], r[1], r[2], r[3], r[4]
        if not name or name in BORING_NAMES and lang != "java": continue
        if lang == "java" and (mfn.startswith(BORING_PREFIX) or name in ("<init>",) and mfn.startswith(BORING_PREFIX)): continue
        if mfn.startswith("__ecma") or mfn.startswith("__whatwg.console"): continue
        key = mfn.split(":")[0] if (lang == "java" and mfn and "<unknown" not in mfn) else f"{recv.split('.')[-1]}.{name}"
        if key in seen: continue
        seen.add(key)
        out.append({"id": len(out), "key": key, "name": name, "recv": recv, "mfn": mfn, "example": ex, "count": int(cnt)})
    return out

def ask(client, model, batch):
    lines = [f'{c["id"]}. api: {c["key"]}   | usage: {c["example"]}' for c in batch]
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n".join(lines)}]
    t = time.time(); err = ""; text = ""
    for attempt in range(3):
        try:
            r = client.chat.completions.create(model=model, messages=msgs, temperature=0, max_tokens=2500)
            text = r.choices[0].message.content or ""; usage = (r.usage.prompt_tokens, r.usage.completion_tokens); break
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {str(e)[:200]}"; usage = (0, 0); time.sleep(2 * (attempt + 1))
    with TRACE.open("a") as f:
        f.write(json.dumps({"ts": time.time(), "model": model, "seconds": round(time.time() - t, 1), "usage": usage, "ids": [c["id"] for c in batch],
                            "request": msgs[1]["content"], "response": text, "error": err}) + "\n")
    return text, err

def parse(text):
    m = re.search(r"\[.*\]", text or "", re.S)
    if not m: return None
    try: v = json.loads(m.group(0))
    except ValueError: return None
    return v if isinstance(v, list) else None

def to_spec(c, role, cls, arg, lang, model):
    spec = {"kind": "call", "name": re.escape(c["name"]) if c["name"] != "<init>" else "<init>", "recv": None, "type": None, "ctor": c["name"] == "<init>",
            "arg": arg, "fw": "llm", "rule": f"llm:{model}", "classified_by": "llm", "api": c["key"]}
    if lang == "java" and c["mfn"] and "<unknown" not in c["mfn"] and "<unresolved" not in c["mfn"]:
        spec["mfn"] = re.escape(c["mfn"].split(":")[0]) + ".*"
    else:
        last = c["recv"].split(".")[-1].strip() if c["recv"] else ""
        last = re.sub(r"\(.*", "", last)
        spec["recv"] = re.escape(last) if last and re.fullmatch(r"[\w$]+", last) else None
    if c["name"] == "<init>": spec["name"] = ".*"; spec["ctor"] = True
    return spec

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("tsv"); ap.add_argument("lang"); ap.add_argument("out")
    ap.add_argument("--batch", type=int, default=25); ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    model = os.environ["KAVACH_MODEL"]
    client = OpenAI(base_url=os.environ["OPENAI_BASE_URL"], api_key=os.environ["OPENAI_API_KEY"], timeout=120)
    cands = load(a.tsv, a.lang); TRACE.parent.mkdir(parents=True, exist_ok=True)
    batches = [cands[i:i + a.batch] for i in range(0, len(cands), a.batch)]
    print(f"{a.tsv}: {len(cands)} distinct candidate APIs in {len(batches)} batches (model {model})", flush=True)
    stats = {"batches_failed": 0, "malformed": 0, "invalid": 0, "accepted": 0, "none": 0}
    sources, sinks, sans = [], {}, {}
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for batch, (text, err) in zip(batches, ex.map(lambda b: ask(client, model, b), batches)):
            verdicts = parse(text)
            if verdicts is None: stats["batches_failed" if err else "malformed"] += 1; continue
            byid = {c["id"]: c for c in batch}
            for v in verdicts:
                if not isinstance(v, dict) or v.get("id") not in byid: stats["invalid"] += 1; continue
                c, role = byid[v["id"]], v.get("role")
                if role == "none": stats["none"] += 1; continue
                arg = v.get("arg"); arg = arg if isinstance(arg, int) and not isinstance(arg, bool) and 0 <= arg < 8 else None
                if role == "source": sources.append(to_spec(c, role, "*", None, a.lang, model)); stats["accepted"] += 1
                elif role in ("sink", "sanitizer") and v.get("class") in CLASSES:
                    (sinks if role == "sink" else sans).setdefault(v["class"], []).append(to_spec(c, role, v["class"], arg, a.lang, model)); stats["accepted"] += 1
                else: stats["invalid"] += 1
    data = {"_about": f"LLM-proposed specs ({model}); classified_by=llm; candidate-level, validated against the candidate list", "model": model,
            "candidates": len(cands), "stats": stats, "sources": {"*": sources}, "sinks": sinks, "sanitizers": sans}
    json.dump(data, open(a.out, "w"), indent=1)
    print(json.dumps({"candidates": len(cands), **stats, "sources": len(sources), "sinks": {k: len(v) for k, v in sinks.items()},
                      "sanitizers": {k: len(v) for k, v in sans.items()}}))

if __name__ == "__main__":
    main()
