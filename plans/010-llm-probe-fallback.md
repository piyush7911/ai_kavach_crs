# Plan 010 — LLM probe fallback (for "0 findings on a new app")

**Status:** proposal, for review. **Author:** garv. **Reviewer:** piyush.

## 1. Problem

On a brand-new app our deterministic pipeline can return **0 confirmed bugs** even when bugs exist —
because one of these failed, not because the app is clean:
- **surface not found** — route discovery (crawl + sitemap + param-mine) missed the endpoints/params
  (SPA, unusual framework, odd param names, auth-walled pages);
- **class not covered** — the bug's class has no probe family (business logic, unusual auth flow, an
  injection in a context our fixed payloads don't hit);
- **payload style wrong** — the family exists but its payloads don't trigger this app's shape
  (we saw exactly this: numeric vs quoted vs presence-flip SQLi).

We want an **LLM fallback** that raises recall on unknown apps **without weakening our one hard guarantee:
precision = 1.0 (a finding exists only if a real exploit fired).**

## 2. Principle (non-negotiable)

**The LLM proposes; the deterministic oracle decides.** The current research consensus (RECEIPT, AXE,
OpenAnt, Shannon) is that LLM pentest agents only produce trustworthy results when a deterministic
verifier confirms exploitation — "proof of exploitation, not a theoretical match." That is already our
architecture. So the fallback is an **attack GENERATOR**, never a judge: it emits candidate exploits in
our existing contract, and `run_exploit` confirms or discards them. **The LLM can never put an unproven
bug in the report.** This keeps false positives impossible by construction.

## 3. Trigger

Runs **only when the deterministic pass yields 0 (or below a threshold)** confirmed findings — it is a
fallback, not the default path (cost + Rules of Engagement). CLI: `kavach --url … --llm-fallback`.

## 4. Architecture — two slices, both feeding the existing oracle

```
deterministic pass → 0 confirmed ?
        │ yes
        ▼
 [A] LLM surface discovery  ──►  extra Routes (method, path, params, auth)
        │                                  │
        ▼                                  ▼
 [B] LLM attack-hypothesis ──►  exploit-dicts (our contract) ──► run_exploit() ──► confirmed / discarded
        ▲                                                             │
        └──────────────── response fed back (bounded agentic loop) ◄──┘
```

**Slice A — LLM surface discovery.** When discovery found little, give the LLM the homepage HTML/JS
(and source, if `--target`), ask it to propose `{routes, params, how-to-authenticate}`. Feed into the
same `Route` list the probes already consume. (This is the white-box trick Shannon tops the XBOW
benchmark with.) Highest value, because "0 bugs" is most often "we never found the attack surface."

**Slice B — LLM attack-hypothesis generation.** Give the LLM the discovered routes + a few real
request/response samples; ask it, per endpoint, for `{class, payload, oracle-spec}` **in our exploit
JSON** (differential / marker / metamorphic / redirect / oob). `run_exploit` replays it. Confirmed → real
bug (and it already carries the replayable PoC + enrichment). Covers classes/contexts our fixed families
miss.

## 5. The hard constraint: output must be our exploit contract

The LLM must emit **only** the JSON shape `run_exploit` already understands
(`{method, path, body, login_as, success_if}` or `{differential|idor|access_control|write_idor|oob: …}`).
Use structured/validated output; reject anything that doesn't parse to the schema (same discipline as the
repair loop rejecting non-parsing patches). This is what lets the existing, trusted oracle do the judging.

## 6. Safety / RoE / air-gap

- **RoE**: payloads constrained to non-destructive classes (no DoS/flood/ReDoS); every request goes
  through the existing global throttle; loopback/own-instance only. The LLM prompt forbids destructive
  actions and we filter the generated exploits against an allowlist of classes before replay.
- **Air-gapped**: uses the same local OpenAI-compatible endpoint (codegemma / nemotron) — no cloud.
- **Bounded**: N attempts per route, hard request budget (like `mine_params`), so it can't run away.
- **Additive & reversible**: it only adds confirmed findings; it cannot regress or false-positive.

## 7. What it will / won't catch

- **Will**: endpoints/params we couldn't discover; injection/redirect/ssrf/traversal/xss in contexts our
  fixed payloads miss; simple multi-step flows the LLM can script into `setup` steps.
- **Won't (honest)**: deep business-logic flaws (~70% of critical web bugs) — no agent does these
  reliably yet. We don't claim it.

## 8. Risks

| risk | mitigation |
|---|---|
| weak local model → weak payloads, still 0 | strictly additive (never worse); use the strongest local model available |
| LLM emits malformed/destructive attacks | schema-validate + class-allowlist + throttle before replay |
| cost / time on every run | fallback only (fires on 0), bounded attempts + budget |
| over-claiming | nothing reported unless our oracle fires — precision guarantee unchanged |

## 9. Phased implementation

1. **Slice A** (`probes/llm_surface.py`): `propose_routes(pages, source, llm) -> [Route]`; wire into
   `kavach._dynamic` as a fallback source when route/param discovery is thin. *(smallest, highest value)*
2. **Slice B** (`probes/llm_attacks.py`): `propose_exploits(routes, samples, llm) -> [exploit]`;
   schema-validate; replay via `run_exploit`; emit confirmed Findings.
3. **Agentic loop**: feed the response back for refinement, bounded; stop on first confirm per route.
4. **Eval**: measure recall uplift on a held-out app with the deterministic families *disabled*, to
   prove the fallback stands alone. Keep precision at 1.0 (must stay, by design).

## 10. Open questions for piyush

1. Trigger threshold — only on **exactly 0**, or also "fewer than expected / low coverage"?
2. Slice A reads source/HTML/JS — scope of what we feed the model (token budget on a big app)?
3. Should Slice B's confirmed findings flow straight into the **fix** loop, or report-only first?
4. Reuse the existing flow-classifier model wiring, or a separate fallback model/endpoint?
5. Class allowlist for generated payloads — agree the list (exclude anything DoS-adjacent for RoE)?

## References
- RECEIPT (deterministic verification of agentic XSS) · AXE (grey-box exploitability confirmation)
- OpenAnt (decomposition + adversarial verification + dynamic testing) · Shannon (white-box, XBOW ~96%)
- "LLM Agents for Automated Web Vulnerability Reproduction: Are We There Yet?" (limitations)

---

## 11. Agreed decisions (garv + piyush) — this section is now the source of truth

**Shared position:** use **source + live endpoint together**. Source says *where* to attack; the live
endpoint says *whether it fires*. The LLM reads code, proposes suspects, writes exploits — **deterministic
code decides** (did the exploit fire, did the patch stop it, does the app still work). Every *reported*
finding still has a replayable exploit behind it.

**Statuses & reporting**
- `confirmed` = an exploit fired. `candidate` = LLM/rule suspects it, no proof. Reports show both,
  clearly separated (honest benchmark numbers).
- **Patch only `confirmed`.** Candidates are report-only unless a human approves.
- **Zero findings is never "safe".** The report must show **coverage**: how many routes/handlers were
  examined and how many were actually *exercised*. (New requirement — see Phase 0.)

**Resolved open questions**
1. **Trigger** — not just exactly 0. With source, trigger on a **coverage gap**: any source-mapped route
   no probe exercised, or any suspect left unconfirmed (3/80 routes is still a gap).
2. **Source to feed** — one handler at a time + its callers, imports, middleware (~6k tokens/unit); rank
   handlers by risk (reads request params / has a dangerous call); skip tests/node_modules/vendored/
   generated; **cache by code hash**. Homepage HTML/JS only when there is no source (SPA front end).
3. **Confirmed → fix loop: yes**, with the policy gate + variant check. Unconfirmed = report-only.
4. **Model wiring** — reuse `llm_client` / endpoint + model pinning / audit trace, but add its own role
   **`MODEL_PROBE`** (exploit-gen may need a stronger model than classification). Pinning rules still apply.
5. **Payload class allowlist** — SQLi/NoSQLi, command & code injection, path traversal, SSRF-to-loopback,
   open redirect, reflected & stored XSS, XXE, SSTI, IDOR & access control, mass assignment, missing CSRF,
   JWT misuse, deserialization — all with **harmless markers** (`7*3`→`21`, read a known file, `echo`).
   **Block:** DoS, ReDoS, rate-limit floods, brute force, anything that deletes/overwrites data beyond
   test records, and any request to a non-loopback host.

**Deployment defaults (accepted)**
- **Endpoint** = a disposable **test instance**, so state-changing exploits are allowed on test data.
  (If ever pointed at prod → read-only confirmation mode.)
- **No restart of the original** — patch a **copy** served on a separate port to verify; original
  untouched. *(jsauto/pyauto already copy; javaauto patches in place then restores — acceptable, revisit
  if we want strict copy-only for Java too.)*
- **Credentials** = assume **two test users** given → IDOR / access-control can be `confirmed`; without
  them they stay `candidate`.
- **Network/model** — finale is **air-gapped**, so assume the model is **local** (`MODEL_PROBE` →
  codegemma/nemotron on the local endpoint). If a VM can reach a cloud API, that's a bonus, not assumed.

## 12. Revised phasing (supersedes §9)

- **Phase 0 — coverage map + coverage reporting.** Build a per-language **source route map** (handlers
  that read request input) and have `kavach` report `routes_examined / routes_exercised / suspects`.
  This is the prerequisite for the gap-based trigger and the "0 is never safe" requirement.
  *Note:* JS has this via `flow.py` entries; Python/Java need lightweight route-from-source extraction
  (approximate with OpenAPI/url_map/sitemap ∪ crawl vs probed until per-lang source maps exist).
- **Phase 1 — Slice A (surface discovery).** `propose_routes(handler_units | html_js, llm) -> [Route]`,
  risk-ranked, code-hash-cached; fill the coverage gap; feed the probe.
- **Phase 2 — Slice B (attack-hypothesis gen).** `propose_exploits(route, samples, source, llm)` →
  schema-validated exploit dicts (class allowlist) → `run_exploit` confirms → confirmed Findings.
- **Phase 3 — fix integration.** Confirmed fallback findings flow into the existing repair loop (policy
  gate + variants). Candidates report-only.
- **Phase 4 — eval.** Recall uplift on a held-out app with deterministic families disabled; precision
  must stay 1.0.
