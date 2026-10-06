# Research: Shannon and Strix — what to adapt (2026-10-07)

Cloned read-only into `benchmark_workspace/public/{shannon,strix}` (not used in any benchmark run; study only).
Both are commercial-grade "proof-by-exploitation" AI pentesters — same core principle as our new precision-first rule.
Strix is Apache-2.0 (code freely reusable); Shannon open-source edition is AGPL-3.0 (copyleft — adapt ideas/patterns, don't vendor code without checking license obligations).

## 1. Shannon — validates our scope-narrowing decision, nothing structurally new to copy
Shannon's entire "coverage" is 5 classes: Broken Authentication, Broken Authorization, Injection, XSS, SSRF — stated
plainly in `docs/coverage-roadmap.md` and `docs/safety.md`. Explicit quote: *"this also means Shannon does not aim to
report every possible security issue... many dependency, policy, configuration, and broad static-analysis findings are
outside the core Shannon workflow."*

**Why this matters for us:** a funded, production commercial tool made the exact same call we're being forced into
(precision over coverage) and says so openly rather than hiding it. This is direct external validation that
restricting the *reported* tier to exploit-confirmable classes is the right trade, not a compromise unique to us.
Adopt the framing: state our covered classes plainly in any submission doc, same as their README/docs do.

Nothing else in Shannon's public repo is architecturally novel to us (it's mostly a CLI/docs wrapper over a closed
agent); the open-source repo doesn't expose its exploitation internals in a way worth mining further.

## 2. Strix — several concrete, adoptable patterns

### a. A reporting tool that is itself the FP gate (`strix/tools/reporting/tool.py`)
This is the single most directly applicable thing. `create_vulnerability_report` **refuses to file** unless:
- `poc_script_code` is non-empty ("PoC script/code is REQUIRED — provide the actual exploit/payload")
- `evidence` is non-empty ("concrete proof of the finding")
- `counterevidence` is non-empty — the agent must state *the strongest evidence against its own finding*, or what
  it checked and found none of (their example: "no input validation, WAF, or authorization check found on this path")
- `confidence` is one of a fixed set, and if not `"high"`, `confidence_rationale` is mandatory, naming the specific
  gap (their example: "static-only trace, unconfirmed reachability, no runtime access")
- if any `code_location` carries a proposed fix (`fix_after`), `fix_verification` is mandatory and must state, in
  order: (1) re-traced source→sink through the *patched* code and why it's now blocked, (2) a bypass review — reread
  the diff without the original rationale and name equivalent sinks/sibling call sites/alternate input classes
  checked, (3) what legitimate behavior still works, (4) which of these were executed vs. reasoned, naming any unrun
  check as an explicit gap. If the agent can't state this, the instruction is literally "drop `fix_after`".

**This is a better-specified version of exactly what we need for the PROVE-stage precision gate.** It encodes the
reviewer's job *into the tool's input schema*, so a sloppy or hallucinated finding is rejected before it's ever
written anywhere, not caught by a downstream human. Directly portable to `src/jsauto/repair.py` / a new
`create_finding` gate: require `counterevidence`, `confidence` + rationale, and a structured `fix_verification`
before any finding/patch leaves `candidate` status.

### b. HTTP evidence is cross-checked against a real proxy log, not trusted from the agent's prose
`_verify_http_exchange_ids` (same file): a finding can cite `http_exchange_ids`, but each id is checked against the
live Caido proxy project; an id the proxy doesn't actually have is **rejected outright** ("do not exist in the
current proxy project"), and if the proxy can't be reached the ids are dropped with a warning rather than silently
trusted. The agent cannot claim "I saw X in the response" — it must cite a request id that a real intercepting proxy
independently recorded.

**Adaptable:** our oracle engine (`benchmarks/oracles.py`) already does something similar in spirit (control request,
replay) but doesn't force the *finding record itself* to carry a verifiable, independently-logged reference to the
actual request/response. Routing all exploit traffic through a lightweight logging proxy (even a simple local
mitmproxy/custom logger keyed by request id) and requiring every reported finding to cite logged exchange ids would
close a real gap: today a finding's evidence is whatever the patch-loop code asserts happened, not an independently
queryable record.

### c. Coverage ledger — "what we looked at and how it closed", separate from findings
`strix/tools/coverage/tool.py`: every agent records entries with `outcome` in
`{reported, no_issue_found, ruled_out, not_applicable, needs_follow_up}`, and an entry with `ruled_out`,
`not_applicable`, or `needs_follow_up` **must carry evidence** too. Their comment explains the point precisely:
*"Findings answer 'what did we find'. Coverage answers 'what did we look at, and how did each one close' — the
negative space a client report needs to be trustworthy."*

**Adaptable:** this is exactly the "zero findings is never 'safe'" principle already in our docs
(`ARCHITECTURE_EXPLAINED.md` §9), but Strix operationalizes it as a tracked, evidenced ledger rather than a prose
caveat. We could add a `coverage.json` alongside `evidence.json` in the `fix` command output: for every route/class
pair examined, record why it closed (probed-and-clean / no-oracle-for-class / skipped-by-policy / confirmed), each
with its own evidence requirement for the non-`reported` outcomes.

### d. Multi-agent graph with a parent-readable, structured completion report
`strix/tools/agents_graph/tool.py`: a spawned agent's `agent_finish` free-text summary is *not* trusted as the
authoritative record of what it found — `_filed_reports_by(agent_id)` reads back the actual filed report ids from
report state and renders them as "authoritative; use these ids" separately from the agent's prose summary.
`view_agent_graph` lets any agent see the whole tree (parent/child/status) before spawning a new one, explicitly to
avoid duplicate work.

**Adaptable:** if Kavach ever runs multiple finding-confirmation agents concurrently (e.g. one per bug class), the
same split — structured, store-backed "what was actually filed" vs. the agent's own narrative — avoids a swarm
over-reporting because a sub-agent's summary oversold what it proved.

### e. Threat model as a shared, versioned, run-scoped document (`strix/tools/threat_model`)
One agent derives trust boundaries/attack surface/severity calibration once per target identity; every other agent
on the same run reads it back instead of re-deriving it, and it's keyed by a *normalized* target identity (handles
the same app being referenced by URL, page, or checkout path within one run) so agents converge on one document.
Minimum size/section requirements (`overview`, `trust boundaries`, `attack surface`, `severity calibration`) are
enforced before it's accepted.

**Adaptable:** we don't currently have a shared severity/trust-boundary baseline across our detectors (taint /
misuse / live) — each scores independently. A lightweight shared "target model" (what's the trust boundary, what's
critical here) that the live-check severity logic and the misuse catalogue both read would make our combined
reporting more consistent, especially as we add more apps.

### f. Scan-mode skills with explicit tool sequencing (`strix/skills/scan_modes/{quick,standard,deep,diff}.md`)
Not just prompts — concrete phased procedure: Phase 1 reconnaissance names exact CLI tools to run in order (`semgrep`,
`ast-grep`, `gitleaks`, `trufflehog`, `trivy fs`, a mandatory Tree-sitter/AST pass with artifacts reused downstream),
Phase 2 is structured business-logic modeling (user flows, state machines, trust boundaries, invariants), Phase 3 is
exhaustive input-vector testing. This is effectively a written-out version of "our route map → taint → misuse →
live" pipeline, but authored as agent instructions rather than code.

**Adaptable:** nothing structurally new (we already do route-map → taint → misuse → live in that order), but the
`diff.md` mode (scan only what changed) is a gap we don't have — useful for a CI/PR-gating story if the finale or a
follow-on wants incremental scanning instead of full-repo every time.

### g. A library of 27 per-vulnerability-class technique skills (`strix/skills/vulnerabilities/*.md`)
e.g. `idor.md` catalogues reference locations (path/query/body/header/cookie/JWT claim/GraphQL arg/WebSocket/gRPC),
identifier forms (int/UUID/ULID/Snowflake/slug/composite/opaque), relationship-reference field names
(`ownerId`/`tenantId`/`projectId`/…), expansion/projection parameter names that bypass authorization in resolvers
(`fields`/`include`/`expand`/`populate`), and concrete enumeration techniques (type confusion, parameter pollution,
case aliasing, path-traversal-style virtual-FS tricks). Also covers `nosql_injection`, `mass_assignment`,
`race_conditions`, `prototype_pollution`, `http_request_smuggling`, `llm_prompt_injection`, `agentic_system_security`
— several classes we don't detect or even name anywhere in Kavach.

**Adaptable, concretely:** `idor.md`'s field-name and parameter-name lists are exactly the kind of generic,
framework-agnostic data our misuse catalogue / route-map layer is missing for IDOR detection (we currently have
*no* IDOR detector beyond the project's hand-built two-user oracle for specific apps). Mining this skill file's
vocabulary into a data file (`knowledge/idor_fields.json`: relationship-reference names, expansion-param names) would
let the route-map step flag "this route's object parameter matches a known ownership-reference name and there's no
visible ownership check" as an IDOR *candidate* for live two-user confirmation — closing exactly the IDOR gap called
out repeatedly in our own benchmark runs (NodeGoat idor-alloc/idor-benefits, VulnerableApp
INSECURE_DIRECT_OBJECT_REFERENCE, VAmPI bola-*).

## Summary: concrete next steps, ranked by fit with our current FP-zero constraint
1. **Port the reporting-gate schema** (counterevidence, confidence+rationale, fix_verification) into our own finding/patch
   record before anything is marked `reported` — directly enforces what we agreed to in the precision-first rule.
2. **Mine `idor.md` (and the other 26 skill files) into data**, same pattern as the Semgrep taint-rule mining already
   done — closes our biggest named gap (IDOR) with zero new infrastructure, feeding the existing two-user live oracle.
3. **Log all exploit HTTP traffic to an independently queryable store**, and require findings to cite a logged
   exchange id — makes "confirmed by a live exploit" an audit-checkable claim instead of trusted code-path assertion.
4. **Add a coverage ledger** (`coverage.json`) with the same `reported/no_issue_found/ruled_out/not_applicable/
   needs_follow_up` vocabulary, evidenced for every non-`reported` outcome — turns "zero findings isn't safe" from a
   doc caveat into a per-route checkable record.
5. Lower priority: shared threat-model doc (d), scan-mode `diff` mode for incremental scans (f) — useful later, not
   blocking the FP-zero goal.

Nothing here was implemented; this is research only, per the standing rule to confirm before feature changes.
