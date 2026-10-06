# AI Kavach CRS — results report (NodeGoat + VAmPI)

A run of the full solution against the two primary benchmark apps, measured live. Numbers are from
`benchmarks/bench.py` (3 runs each), the static detectors, and the autonomous repair drivers. Every
"confirmed" below means a real exploit was replayed against the running app and succeeded — not a static
guess. Static-only and Rules-of-Engagement-excluded classes are scored separately, never hidden.

## 1. What the solution does (one paragraph)

Point it at an app: it **detects** candidates (static rules per language), **discovers + confirms** bugs
over HTTP (route discovery → oracle probes that prove exploitability), and **fixes + proves** (a local
LLM rewrites the vulnerable function; deterministic gates accept the patch only if the exploit is gone,
normal use still works, and attack variants are also blocked). The verification layer speaks HTTP, so it
is language-neutral; only the static rules and the patch splicer are per-language.

## 2. Headline results (live, 3 runs each)

| App | Stack | Static candidates | Confirmed (recall) | Precision | Stability (3 runs) | Speed | Autonomous fix |
|---|---|---|---|---|---|---|---|
| **NodeGoat** | Node.js | 15 (12 classes) | **7 / 7 = 1.0** | **1.0** | 0.93 Jaccard | 1.1 s/bug | 5/6 (nemotron) · 4/5 (codegemma) |
| **VAmPI** | Python | 4 | **7 / 7 = 1.0** | **1.0** | 1.0 Jaccard | 2.1 s/bug | 5/6 (nemotron) · 3/6 (codegemma) |

- **Recall 1.0** — every in-scope (dynamically reachable) bug confirmed, both apps.
- **Precision 1.0** — zero false positives: a finding exists only if its exploit fired.
- **Cost $0** for discovery+confirm — deterministic, model-free (model is used only for the fix step).
- NodeGoat stability 0.93 (not 1.0): one of three runs confirmed 6/7 — the benefits write-IDOR
  occasionally flakes on the Mongo-seeded fresh instance; the other two runs got 7/7.

## 3. NodeGoat (Node.js) — per stage

**Detect (static, `jsauto`):** 15 findings across 12 classes — nosql-injection, eval-injection, xss,
ssrf, open-redirect, idor ×2, redos, private-key-in-repo, hardcoded-secret ×4, insecure-session-cookie,
csrf-missing.

**Discover + confirm (HTTP oracles):** 7/7 in-scope confirmed:

| bug | oracle |
|---|---|
| NoSQL injection | differential (true vs false condition) |
| eval injection | marker (`6*4` → `24`) |
| Stored/reflected XSS | marker reflected un-escaped in HTML |
| SSRF | out-of-band callback to our listener |
| Open redirect | Location header to our domain |
| IDOR (allocations, read) | two-id read-diff |
| IDOR (benefits, write) | verify-after-write (marker written as non-owner, read back) |

Out of scope: ReDoS (RoE: live proof = DoS), 4 static-only (secrets/key/cookie/CSRF).

**Fix + prove (`ngautofix`, local model):** 5/6 proven with nemotron-30b (nosql, eval, open-redirect,
ssrf, read-IDOR; 3 hardened), 4/5 with codegemma-7b. Each patch rebuilt nothing (Node is interpreted) and
was accepted only after the exploit no longer reproduced + 13 golden regression flows passed + attack
variants were blocked. The misses were gate-*rejected*, never shipped.

## 4. VAmPI (Python) — per stage

**Detect (static, `pyauto`):** 4 findings (hardcoded-secret ×3, Flask debug=True). VAmPI's bugs are
mostly authz/logic/behaviour, invisible to static reading — which is the point of the dynamic layer.

**Discover + confirm:** 7/7 in-scope confirmed — SQL injection (differential), BOLA password-change,
BOLA email-change, books-BOLA (metamorphic, with resource-setup), mass-assignment, excessive data
exposure, user enumeration. Discovery is **spec-free**: routes read from the app's OpenAPI or live
url_map; proven to work with the spec removed.

Out of scope: ReDoS + rate-limiting (RoE), weak-JWT (static-only).

**Fix + prove (`pyautofix`, local model):** 5/6 proven with nemotron-30b (SQLi, both BOLAs, books-BOLA,
enumeration; only the debug data-dump missed), 3/6 with codegemma-7b. Every unsafe patch rejected by the
regression gate.

## 5. Beyond these two apps (same engine)

- **Third language proven:** OWASP VulnerableApp (Java/Spring) — static detection (6 classes), SQLi
  confirmed over HTTP, and a SQLi fix proven end-to-end with codegemma (rebuild-and-replay gate). Full
  find→fix→prove on a stack the engine was never written for.
- **Industry scanners folded in** (one unified runner, `benchmarks/kavach.py`):
  - **ZAP** and **Nuclei** — their alerts are re-tested by our oracle (real → confirmed, false positives
    → dropped), and their spidered routes/params feed our discovery.
  - **Trivy** — dependency CVEs / IaC / secrets (the SCA layer we don't cover); surfaced 92 real CVEs on
    NodeGoat's lockfile. Reported, not auto-fixed (a version bump can break the app and can't be proven).
- **One command, any app:** `python -m benchmarks.kavach --target DIR --url URL [--zap/--nuclei/--trivy]`
  auto-detects the stack, runs static + dynamic + scanner ingest, and emits one merged report
  (confirmed vs candidate).

## 6. What the metrics mean (and honest limits)

- **"Confirmed" = replayed exploit succeeded.** That is why precision is 1.0 — there is no triage queue
  of maybe-bugs, unlike a scanner's output.
- **Recall is over in-scope bugs** (dynamically reachable). RoE-forbidden classes (ReDoS, rate-limiting
  — a live proof is a denial of service) and static-only classes (secrets, weak key) are reported
  separately, not counted against recall. Counting them would be dishonest either way.
- **Fix is model-bounded, not safety-bounded.** The gates reject every bad patch; a stronger model
  raises the fix rate, a weaker one lowers it, neither ships a regression.
- **Stability** (run-to-run Jaccard) is the autonomous-run metric: VAmPI 1.0, NodeGoat 0.93.

## 7. One-line thesis

Scanners (ZAP / Nuclei / Trivy / Semgrep) hand you a list of alerts to triage. This system **confirms**
each by exploiting it, **fixes** it with a local model, and **proves** the fix — autonomously, across
three languages, on apps it was never written for.

*Raw metrics: `reports/bench_vampi.json`, `reports/bench_nodegoat.json`. Fix detail:
`reports/model_comparison.md`. Per-vuln generalisation: `reports/vuln_coverage.md`.*
