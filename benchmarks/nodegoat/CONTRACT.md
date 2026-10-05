# Track 1 ↔ Track 2 contract (NodeGoat benchmark)

The interface between the **engine** (`src/jsauto/`, Track 2) and the **harness**
(`benchmarks/nodegoat/`, Track 1). Verified working 2026-10-05: the engine's real
`reports/special/nodegoat_findings.json` scores against this manifest end to end.

## Runner CLI (Track 1 owns; the engine calls it)

    python -m benchmarks.nodegoat.runner start   --tree DIR [--json out]
    python -m benchmarks.nodegoat.runner replay   --tree DIR --exploit E.json [--json out]
    python -m benchmarks.nodegoat.runner regress   --tree DIR [--flows F] [--json out]
    python -m benchmarks.nodegoat.runner score     --findings F --manifest M [--json out]

Exit codes: `replay` 0 = NOT exploitable (fixed/safe), 1 = exploitable, 2 = error.
`regress` 0 = all flows match golden, 1 = diverged, 2 = error. These map directly
onto the DRV loop's `pov_command` (replay) and `test_command` (regress), so the
repair loop wires in with no new gate code:

    pov_command  = python -m benchmarks.nodegoat.runner replay  --tree {tree} --exploit {exploit}
    test_command = python -m benchmarks.nodegoat.runner regress --tree {tree}

Each call runs the tree in isolation: own free port, own Mongo DB (dropped on stop),
loopback only (`loopback_preload.js`), every request throttled.

## Exploit request (either track may emit; `replay` consumes)

    { "method", "path", "headers"?, "body"?, "login_as": "user|admin|none",
      "follow_redirects"?: false,
      "success_if": { "status"?, "body_regex"?, "redirect_regex"?, "oob_marker"? } }

This is exactly the engine's `Finding.exploit` field (`src/jsauto/findings.py`).
When a probe fills `exploit`, the same object goes straight to `replay`.

## Finding (engine emits; `score` consumes)

`src/jsauto/findings.py` `Finding` → `dump()` writes `{"findings": [...], ...}`.
`score` accepts that object or a bare list. It reads `file` (POSIX, relative to the
tree root) and `line`; everything else is ignored by scoring.

## Scoring (Track 1 owns)

`score` matches a finding to a manifest vuln on **file + line proximity only**
(±5 lines; line 0 = whole file, for config/dependencies). It deliberately does NOT
match on class name or CWE, because the two sides use different vocabularies and a
shared vocabulary is not worth enforcing. recall = distinct vulns hit / total;
precision = findings hitting a real vuln / total findings.

Baseline (engine static detection only, 2026-10-05): **recall 0.727 (8/11),
precision 0.81**. Missed NG-03 (IDOR), NG-06 (XSS), NG-07 (CSRF) — none is
statically detectable; they need the engine's dynamic probes (2.3), which emit an
`exploit` that `replay` then confirms.

## Open decisions (need the team / the rules)

1. **Do seeded test credentials and dev/test config secrets count as defects?**
   The engine flags `artifacts/db-reset.js`, `config/env/development.js`,
   `config/env/test.js`; the manifest does not. This is the ~4 findings that pull
   precision below 1.0. Decide whether to add them to the manifest or treat them as
   expected false positives.
2. **Is the session-cookie weakness (`server.js:78`, CWE-522) its own vuln?**
   The engine emits it; the manifest folds it into NG-08. Add NG-12 if yes.
3. **Is querying the npm registry allowed at the event?** The engine's dependency
   audit needs it. If not, we need a vendored advisory snapshot (RoE: declared
   resources / no unauthorized external network).
4. **IDOR / XSS / CSRF** reach the manifest only once the engine's probes produce a
   confirming `exploit`. Until then they sit as `validation: inspection`.
