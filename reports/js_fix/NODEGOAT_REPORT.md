# NodeGoat — findings and fixes report

Target: OWASP NodeGoat (commit c5cb68a). Run on Track 1's Mac (NodeGoat + MongoDB 4.4 +
runner), model `gemma4:e2b` over LAN (no cloud). Numbers are from real runs, not estimates.

## Headline

| | |
|---|---|
| Real vulnerabilities in the answer key (`manifest.json`) | 12 |
| Detected (engine static scan) | 9 / 12 |
| Exploit proven to work (Track 1 ground truth) | 9 |
| Fixed end-to-end by the local model | 1 proven + hardened |
| Fake fixes that slipped through | 0 |

## 1. What we could find (detection)

Engine static scan found 9 of 12.

| Found | Missed (need a live probe, not static reading) |
|---|---|
| NG-01 eval injection | NG-03 IDOR |
| NG-02 NoSQL injection | NG-06 stored XSS |
| NG-04 open redirect | NG-07 missing CSRF |
| NG-05 SSRF | |
| NG-08 hard-coded secret | |
| NG-09 committed private key | |
| NG-10 ReDoS | |
| NG-11 vulnerable dependencies | |
| NG-12 insecure session cookie | |

Track 1 has working exploits for the three misses (IDOR, XSS, CSRF); wiring them into the
engine's live probes is the open detection item.

## 2. What we could attack (Track 1 exploits = ground truth)

Confirmed, replayable exploits for 9 bugs; 8 proven both directions (works on the vulnerable
tree, stops on a correct fix): eval, NoSQL, IDOR, open redirect, SSRF, XSS, session cookie,
plus CSRF (confirmed on the vulnerable tree). Secrets, private key, ReDoS and dependencies are
confirmed by inspection/audit — no safe live exploit (a live ReDoS PoV is a denial-of-service,
which the Rules of Engagement forbid).

Each has alternate-encoding variants for hardening (the web analogue of re-fuzzing).

## 3. What we could fix end-to-end (detect -> confirm -> local model patch -> gates)

Full run across all findings, `gemma4:e2b`, 3 attempts each (`reports/js_fix/full/`):

| Outcome | Count | Which |
|---|---|---|
| Proven + hardened | 1 | NG-01 eval injection (`eval(...)` -> `Number(...)`) |
| Correctly refused (not a code fix) | 1 | NG-09 private key — remove the key, don't patch code |
| Unresolved (no passing patch in 3 tries) | 15 | the rest |
| Error | 1 | NG-08 hard-coded secret |

The one green is real: exploit blocked, every variant blocked (hardened), all 12 regression
flows pass — on the weakest local model, air-gap compatible. 17 model calls, ~7 min total.

## 4. Honest caveats

- Low fix yield is the model, not the pipeline. `gemma4:e2b` is tiny; its patches mostly
  failed at the parse stage (invalid code output), and the gates rejected every one. The
  verification works for all 12 (hand-written correct fixes pass every gate). A stronger local
  coding model (e.g. a qwen-coder) is the lever for yield — not model-in-the-cloud (banned) and
  not deterministic templates (do not generalise across languages).
- Only 1 bug confirmed a live exploit in the full run: most classes lack a dynamic probe oracle
  yet (NoSQL, ReDoS, dependencies, secrets), so they are repaired without a PoV gate and never
  reported `proven` — honest by design, but it caps the end-to-end `proven` count.
- The combined all-patches tree broke (`start=fail`) — accumulating 18 mostly-failing patches
  corrupted the tree. Isolated proven patches (eval) are fine. Flagged for Track 2.

## Bottom line

Find 9/12. Attack 9 with real exploits. Fix end-to-end on the weakest local model: 1 proven,
0 fakes. Safety is intact (nothing false shipped). The two named, fixable levers: a stronger
local coding model (yield) and live probes for IDOR/XSS/CSRF (detection).

## Update (2026-10-06): 4 proven end-to-end + overfitting check

After wiring the NoSQL differential oracle and the XSS probes, the full CodeGemma run (local, no
cloud) now proves and hardens **4 of the 5 confirmable bugs**: eval, NoSQL, SSRF, XSS. Only
open-redirect is unresolved (every model fails it; it is the template candidate). proven: 2 -> 4.

**Overfitting check (important for credibility).** NodeGoat ships the fix for each bug as a comment
(e.g. `// const preTax = parseInt(...)` right inside the eval function). To rule out the model just
copying the answer, we stripped EVERY comment from the app source (41 files, all still parse) and
re-ran the 4 confirmed classes:

| class | with NodeGoat comments | comments STRIPPED |
|---|---|---|
| eval-injection | proven | proven |
| nosql-injection | proven | proven |
| ssrf | proven | proven |
| xss | proven | proven |

All four stay proven with no fix hints in the source. The model reasons the fix, it does not read
the answer — so these numbers are expected to transfer to the jury's customised app (which has no
such comments). The honest cross-check remains the held-out app (DVNA), not NodeGoat.
