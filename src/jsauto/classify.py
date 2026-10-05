"""
Classifier for calls the knowledge file does not recognise.

The flow analysis finds calls that receive user-controlled data. Most are recognised from the
module they were imported from (config/js_knowledge.json). The rest are a library nobody listed,
or a method on an object the analysis cannot resolve. Dropping them would make recall depend on
the size of a hand-written list, so they are put to a model instead:

    "Does this call turn attacker-controlled data into a vulnerability? Which class?"

Design rules:

  * One question per distinct (module, method), answered once and cached. A scan of a large app
    asks about a handful of distinct calls, not one per call site.
  * The answer is a structured verdict, validated before use. A malformed or non-committal answer
    is treated as "not a sink", never as a guess.
  * Everything the model flags is marked `classified_by="model"` with low confidence. Only a
    replayable exploit against a running instance promotes it to confirmed.
  * A confirmed model-found sink can be written back to the knowledge file (`learn`), which is how
    the catalogue grows from the targets it meets instead of being hand-edited.
"""

import json
import re
from pathlib import Path
from typing import Callable, Optional

CLASSES = ("eval-injection", "command-injection", "sql-injection", "nosql-injection", "ssrf",
           "path-traversal", "open-redirect", "deserialization", "xss", "xxe", "template-injection",
           "ldap-injection", "log-injection", "none")

_SYSTEM = (
    "You are a security code reviewer. You decide whether ONE call in a Node.js application is a "
    "vulnerability sink when attacker-controlled data reaches the argument shown. Reply with a single "
    "JSON object and nothing else: "
    '{"sink": true|false, "class": one of ' + json.dumps(list(CLASSES)) + ', "cwe": "CWE-nnn", '
    '"reason": "one short sentence"}. '
    "Say sink=false for calls that merely store, log, compare, or read data safely, and for calls whose "
    "argument is a parameterised value rather than code, a command, a path, a URL or a query string."
)


def _parse(text: str) -> Optional[dict]:
    """Extract and validate the verdict; anything that does not validate is None."""
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return None
    try:
        v = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(v, dict) or not isinstance(v.get("sink"), bool):
        return None
    if v["sink"]:
        if v.get("class") not in CLASSES or v["class"] == "none":
            return None
        cwe = str(v.get("cwe", ""))
        v["cwe"] = cwe if re.fullmatch(r"CWE-\d{1,4}", cwe) else ""
    return v


def make_classifier(llm, max_tokens: int = 250, learned_path: Optional[Path] = None) -> Callable:
    """A callable `classify(unknown) -> verdict dict | None` backed by `llm.complete`."""
    learned: dict[str, dict] = {}

    def refresh() -> None:
        """Read the cache at call time: another classifier (or process) may have added to it."""
        if learned_path and Path(learned_path).exists():
            try:
                learned.update(json.loads(Path(learned_path).read_text()))
            except ValueError:
                pass

    def classify(u) -> Optional[dict]:
        key = f"{u.module}::{u.callee.split('.')[-1]}"
        refresh()
        if key in learned:
            return learned[key]
        prompt = (
            f"Call: {u.callee}(...)   imported from module: {u.module or 'unknown'}\n"
            f"Attacker-controlled data reaches argument {u.arg_index}: {u.tainted_expr}\n"
            f"Entry point: {u.entry.get('function')} "
            f"({(u.entry.get('route') or {}).get('method', '')} {(u.entry.get('route') or {}).get('path', '')})\n\n"
            f"Code around the call:\n```js\n{u.snippet}\n```"
        )
        text = llm.complete(_SYSTEM, prompt, purpose="sink-classification", max_tokens=max_tokens)
        verdict = _parse(text)
        if learned_path is not None and verdict is not None:
            learned[key] = verdict
            Path(learned_path).write_text(json.dumps(learned, indent=2, sort_keys=True))
        return verdict

    return classify
