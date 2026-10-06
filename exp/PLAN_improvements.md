# Improvement plan: recall / precision / patch / speed / scale (2026-10-07)

Combines gaps measured in our own runs (NodeGoat, VulnerableApp) with web research. Ranked by
impact × (1/cost) for our deterministic-taint + HTTP-oracle + CEGIS-patch, precision-first, air-gapped
stack. Build exp-first, then promote. RoE flags noted (air-gap, shared-state, throttle).

## Measured gaps (ours)
- **Param discovery is the #1 recall limiter.** NodeGoat attack-gap 86% (18/21 routes had no injectable
  param); LLM proposed 0. AND `mine_params` is the #1 speed sink (~6 min, thousands of sequential requests).
- Confirmed is bounded by app state (unseeded/un-authed → authed oracles can't fire → real IDOR/injection
  stay candidate). Need `--auth` + seeding in the run.
- Classes with no oracle stay candidate: mass-assignment (no set-read-back), CORS (detected in live but not
  a confirmed class), GraphQL authz, stored-XSS, logic.
- JS backend thinnest; patching: JS LLM-repair unwired, 3 template classes, no config-fix templates.
- Everything sequential (probes + LLM). Joern CPG rebuilt every run.

## TIER 1 — build first (highest ROI, low cost, air-gap-safe)

### T1. Chunked binary-search param discovery (fixes the #1 recall gap AND the #1 speed sink)
Replace brute `mine_params` with the Arjun/x8 technique: pack MANY candidate param names into ONE request,
binary-split the chunk whose response changes → ~50-60 requests to cover a 25k-name dict (vs thousands).
Oracle = **response-diff** (status / length / word-count / latency / error-string / header / redirect), NOT
reflection — so it finds params with no echo (the auth-gated case). **Stability check first** (send N
identical requests, learn natural variance) so jitter is never a false hit — preserves 0-FP. Inject
candidate names into the AUTHED request (with `--auth`) to hit the gap routes. Double win: recall + speed.
Refs: Arjun (chunk `-c`), x8, Param Miner. Air-gap-safe.

### T2. Two new 0-FP oracle classes — mass-assignment + CORS (header/read-back, no OOB)
- **Mass-assignment (CWE-915):** POST/PUT extra privileged fields (isAdmin/role/verified/is_active — mine
  from `techniques/mass_assignment.json`), GET the object back, diff — confirmed iff the field persisted.
  Two-user variant airtight. Pairs with T1 (discover the hidden writable field, then confirm it stuck).
- **CORS misconfig:** send `Origin: https://evil.<canary>`; confirmed iff response reflects `ACAO: that
  origin` AND `ACAC: true`. Pure header string-check — deterministic, no OOB, trivial. (We detect it in
  live_probes but don't treat it as a confirmed class with a replay; promote to a real oracle.)
Both air-gap-safe (no OOB needed), self-validating, 0-FP.

### T3. Concurrency: bounded worker pool + global req/s token bucket + pooled client
Our Session is sequential urllib. Adopt Nuclei's two-layer model: a bounded worker pool (latency hiding)
capped by a SEPARATE global req/s token bucket (the RoE throttle ceiling — maps cleanly to "throttled
fuzzing"). Pooled client with keep-alive/HTTP-2 (httpx.AsyncClient + Limits + http2, or keep urllib with a
thread pool + token bucket). Multi-x speedup on probes; the token bucket keeps us RoE-compliant regardless
of worker count. Air-gap-safe.

## TIER 2 — solid, moderate cost
### T4. Extend the two-user oracle to GraphQL BOLA/BFLA
Reuse our two-user primitive: auth as A, harvest object IDs from resolver responses, replay as B, confirm B
gets A's object. Add introspection to map resolvers+args for free. Covers OWASP API1/5. GraphQL SSRF on
root-query string args only via the canary (needs self-hosted OOB — air-gap-conditional).
### T5. Differential patch validation from the coverage ledger (strengthens RoE score #3)
PoC fail→pass (exploit must now fail on the patched build) + **replay already-seen good traffic** (from the
exchange log / ledger) through the patched endpoint, assert identical responses = pass→pass behavior proof.
DON'T let the LLM invent the regression set — derive it deterministically from recorded good traffic.
Research pitfall: APR agents misidentify regression tests; our ledger sidesteps it.
### T6. Cached / diff-only CPG per sprint (scalability)
Persist the Joern CPG between 6h sprints; re-scan only changed files against the cached base (CodeQL/Semgrep
diff-aware pattern). Cuts repeated Joern build cost across a sprint's tuning iterations.

## TIER 3 — if time / niche
### T7. Schemathesis in-process 5xx oracle when the target exposes OpenAPI/GraphQL schema
Any 5xx on a schema-valid input = confirmed server error. Cheap stateless win; stateful RESTler-style
dependency fuzzing deferred (higher cost).

## DEFER — RoE shared-state risk (confirm scope before building)
- **Web cache poisoning** (3-request oracle) and **HTTP request smuggling** (timing oracle): high-severity,
  deterministic-ish, but both mutate/observe SHARED state on the target → may be out of RoE scope on a
  shared instance. Flag for the user; do not build until scope confirmed. Smuggling timing also needs a
  calibration knob (jitter margin).

## Recommended first three
T1 (param discovery) → T2 (mass-assign + CORS oracles) → T3 (concurrency). T1 alone is the biggest single
lever (recall + speed); T2 adds breadth at zero precision cost; T3 makes the whole run fast and RoE-clean.
All air-gap-safe, all exp-first.

---
## Build status (2026-10-07)
- **T1 param discovery** ✅ promoted (recall+speed; live-proven id/ipaddress/fileurl; 11.6s→2.8s w/ rate knob)
- **T2 mass-assignment + CORS** ✅ (mass-assign verify-after-write 0-FP; CORS already live)
- **T3 concurrency** ✅ (thread-safe global rate cap + parallel_map; rate knob + worker parallelism)
- **T5 differential patch validation** ✅ (regression set from observed traffic; wired into LLM-fallback)
- **cache-poisoning** ✅ (3-request marker oracle, 0-FP, synthetic cache key; isolated-VM in-scope)
- **request-smuggling** ✅ (CL.TE timing, CANDIDATE-tier — timing isn't a clean proof; 2/2-trial + margin)
- **T4 GraphQL BOLA** ✅ (introspection surface → BOLA candidates → two-user confirm)
- **T6 cached CPG** — DEFERRED: not an engine feature (CPG built by exp Joern scripts); sprint dev-tooling.
- **T7 Schemathesis 5xx** — DEFERRED: needs an OpenAPI-spec input we don't wire; marginal security value.
All promoted, 98 tests green, each 0-FP by construction (candidate tier for timing/unconfirmed).
