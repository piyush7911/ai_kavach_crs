"""P5: mine the Strix vulnerability-technique skill files into per-class vocabulary data (Apache-2.0).

Same pattern as idor_fields.json but automated over all 28 skills/vulnerabilities/*.md. For each class we
extract the generic, framework-agnostic signal a detector can use without the prose: inline-code tokens
(param names, payloads, markers), fenced code blocks (PoC payloads), and section headers (technique
taxonomy). Output: exp/knowledge/techniques/<class>.json. This is DATA to feed candidate detectors later;
the oracle still decides. Several classes get a cheap marker oracle from here (ssti ${7*7}->49,
prototype-pollution __proto__, nosql $ne/$gt operators), to build on top of this data in a follow-up.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SKILLS = Path("benchmark_workspace/public/strix/strix/skills/vulnerabilities")
OUT = Path("exp/knowledge/techniques")
_INLINE = re.compile(r"`([^`\n]{1,80})`")
_FENCE = re.compile(r"```[\w-]*\n(.*?)```", re.S)
_HEADER = re.compile(r"^#{1,4}\s+(.+)$", re.M)
# tokens that look like a param/field/operator/marker worth keeping (drop prose-in-backticks)
_TOKEN_OK = re.compile(r"^[\w.$\-\[\]{}:/@=&?'\"<>()*|+ ]{1,60}$")


def _mine_one(md: str) -> dict:
    inline = []
    for m in _INLINE.finditer(md):
        t = m.group(1).strip()
        if t and _TOKEN_OK.match(t) and " " not in t.strip("`") or len(t) < 24:
            inline.append(t)
    payloads = [b.strip()[:200] for b in _FENCE.findall(md) if b.strip()]
    headers = [h.strip() for h in _HEADER.findall(md)]
    # distinct, order-preserving
    def uniq(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return {"inline_tokens": uniq(inline)[:200], "payloads": uniq(payloads)[:40],
            "sections": uniq(headers)[:40]}


def mine_all() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    summary = {}
    for md in sorted(SKILLS.glob("*.md")):
        klass = md.stem
        data = _mine_one(md.read_text(errors="replace"))
        data["_class"] = klass
        data["_source"] = f"strix/skills/vulnerabilities/{md.name} (Apache-2.0, usestrix/strix)"
        (OUT / f"{klass}.json").write_text(json.dumps(data, indent=1))
        summary[klass] = {"tokens": len(data["inline_tokens"]), "payloads": len(data["payloads"])}
    return summary


if __name__ == "__main__":
    if not SKILLS.exists():
        print(f"skills dir not found at {SKILLS} — clone usestrix/strix into benchmark_workspace/public first")
        raise SystemExit(1)
    s = mine_all()
    print(f"mined {len(s)} technique files -> {OUT}/")
    for k, v in sorted(s.items()):
        print(f"  {k:34} {v['tokens']:3} tokens, {v['payloads']:2} payloads")
