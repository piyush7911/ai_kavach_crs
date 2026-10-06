# Plan: adopt the best of Shannon + Strix (exp first) — 2026-10-07

Builds on `RESEARCH_shannon_strix.md`. Repos cloned read-only under `benchmark_workspace/public/{shannon,strix}`
(gitignored). Strix is Apache-2.0 (reusable); Shannon is AGPL (ideas only). Everything below is built in
`exp/` first and only promoted to `src/` once measured.

## The reframe that makes these a fit
Strix is an LLM agent, so its gates ask the *model* to self-attest (counterevidence, confidence, fix
verification). We are deterministic-first, so for us most of these fields are **filled from the oracle, not
the model** — which is strictly stronger (a replayed exploit can't hallucinate its own counterevidence).
We adopt Strix's *schema* (what a trustworthy finding must carry) and fill it from our engine.

---

## P1 — Reporting-gate schema on our Finding (highest priority, direct FP-zero fit)
Strix's `create_vulnerability_report` refuses to file unless the finding carries a fixed set of fields. Port
the schema as a **validator that blocks promotion to `confirmed`/reported** unless present. Our deterministic
fills in brackets:

| Strix field | required when | our deterministic fill |
|---|---|---|
| `poc_script_code` | always | the replayable `exploit` dict we already attach |
| `evidence` | always | the oracle's `detail` (differential flip, marker, OOB hit) |
| `counterevidence` | always | what the oracle controlled for: "control/benign request NOT flagged; differs only by payload" — we already run the control leg, we just don't record it |
| `confidence` ∈ {high,medium,low} | always | `high` = oracle fired; `low` = candidate (no oracle / static-only) |
| `confidence_rationale` | when confidence != high | the candidate's reason ("static-only trace, no oracle for class, unconfirmed reachability") |
| `severity_change_conditions` | always | one line: what would raise/lower it (e.g. "auth required on this route → lower") |
| `fix_verification` | when a patch is proposed | our gate already proves it: (1) PoV re-traced gone, (2) bypass = hardening-variant replay + sibling sites, (3) regression ok, (4) executed-vs-reasoned. We **run** this; we don't record it structured. |

Exp: `exp/scripts/finding_gate.py` — a `validate_report(finding) -> errors[]` mirroring Strix's required-text
+ analysis-closure + fix_verification checks, plus `fill_from_oracle(finding)` that populates
counterevidence/confidence/rationale from the exploit+detail we already have. Measure: run over our existing
VulnerableApp/NodeGoat confirmed findings — every one must pass the gate (if not, we're under-recording).
Promote to `src/jsauto/findings.py` as fields + a gate that `confirm_candidates`/live/template all call.

## P2 — Coverage ledger (operationalize "0 findings is never safe")
Strix's `coverage/tools.py`: an evidenced ledger separate from findings. Schema (verbatim from the clone):
- entry = `{surface, risk_area, outcome, created_at, evidence?, agent_id?}`, keyed by 6-hex id.
- `outcome` ∈ **`reported | no_issue_found | ruled_out | not_applicable | needs_follow_up`**.
- **evidence is MANDATORY** for `ruled_out | not_applicable | needs_follow_up`; dedupe on
  `(surface.lower(), risk_area.lower())`.
- semantics: ruled_out = disproved a specific candidate (name the control + that it runs on every reachable
  path); not_applicable = risk can't apply (no XML parse → no XXE); needs_follow_up = plausible, unconfirmed
  (name the gap: no creds, service wouldn't start, unconfirmed reachability).

Our `probes.coverage()` already computes examined/attacked/attack-gap but as counts, not an evidenced
per-(route,class) record. Exp: `exp/scripts/coverage_ledger.py` — for every (route, class) pair the run
touched, emit a ledger entry with the right outcome + evidence (confirmed→reported; attacked-clean→
no_issue_found; no-oracle-for-class→not_applicable with "no oracle"; param-gap→needs_follow_up with "no
injectable parameter found"; policy-skipped→ruled_out with the policy rule). Write `coverage.json` beside
the findings. Measure on VulnerableApp: the ledger must account for all 215 routes with an evidenced outcome
each. Promote: `kavach --out` also writes `coverage.json`.

## P3 — IDOR candidate detection from mined vocab (closes our #1 named gap)
We have NO IDOR detector beyond hand-built per-app two-user oracles; IDOR is the most-repeated gap
(NodeGoat idor-alloc/benefits, VulnerableApp IDOR, VAmPI bola-*). Strix's `idor.md` gives the generic,
framework-agnostic vocabulary to flag candidates; our existing two-user oracle confirms. Mine it to data
(done as the first artifact — `exp/knowledge/idor_fields.json`):
- ownership/relationship reference names: ownerId, tenantId, accountId, projectId, teamId, organization,
  subscriptionId, parentId, resourceId, targetId, user_id/owner_id/tenant_id/org_id, X-User-Id/X-Tenant-ID…
- expansion/projection knobs (bypass authz in serializers): fields, include, expand, projection, with,
  select, populate
- identifier forms (guessable): int, UUIDv1, ULID, Snowflake, slug, composite `{orgId}:{userId}`
- reference locations: path, query, body, header, cookie, JWT claim, GraphQL arg, WS/gRPC message

Exp: `exp/scripts/idor_candidates.py` — over the route map, flag a route as an IDOR candidate when an
object-id parameter name matches a relationship-reference name (or the path has an id segment) AND the
handler shows no ownership check (no `ownerId==session.user`, no `@PreAuthorize`, no policy middleware —
best-effort source grep). Emit `candidate` findings → feed the existing two-user metamorphic oracle
(`_access_control` / write-IDOR) for live confirmation. Measure: IDOR candidates proposed vs confirmed on
NodeGoat/VAmPI/VulnerableApp, precision via the oracle (candidates that don't confirm stay candidate, 0 FP).
Promote: a `scanners/idor.py` candidate source + the two-user oracle in the confirm path.

## P4 — HTTP exchange audit log (make "confirmed" audit-checkable)
Strix rejects a finding citing an http exchange id the real proxy didn't record. Today our finding's
evidence is whatever the oracle code asserts — not an independently queryable record. Exp: wrap the oracle's
HTTP client so every request/response is appended to `exchanges.jsonl` with a numeric id; `run_exploit`
returns the ids it used; the finding carries `http_exchange_ids`; a `verify_exchanges(finding, log)` rejects
ids not in the log. Lightweight (our own logger, no mitmproxy needed; air-gap-safe). Measure: every confirmed
finding cites ≥1 real logged exchange. Lower priority than P1-P3 (our replay is already sound; this adds
auditability).

## P5 — Mine the other 27 skill files for breadth (later)
`skills/vulnerabilities/*.md` (28 files) is generic technique data for classes we don't name: ssti,
mass_assignment, prototype_pollution, nosql_injection, race_conditions, http_request_smuggling,
argument_injection, header_injection, open_redirect, insecure_deserialization, path_traversal_lfi_rfi. Same
mining pattern as idor.md → per-class vocab data files feeding candidate detection + an oracle where one is
cheap (SSTI marker `${7*7}`→49; prototype-pollution `__proto__` probe; open-redirect we have). Breadth after
P1-P3 land.

## Shannon — adopt the framing only (no code)
Shannon openly reports just 5 classes and states it does not aim for full coverage. Validates our
precision-first call. Action: in any submission doc, **state our covered/confirmable classes plainly** (and
the candidate tier separately) rather than implying full coverage — same honesty as their docs.

## Build order
1. `idor_fields.json` (data, done first — zero risk).  2. P1 finding-gate (exp) → promote.
3. P2 coverage ledger (exp) → promote.  4. P3 IDOR candidate detector + two-user confirm (exp) → promote.
5. P4 exchange log.  6. P5 breadth mining.
Each measured true/found/confirmed/patched + (new) ruled_out/not_applicable on the same benchmarks.
