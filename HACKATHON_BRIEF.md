# AI Kavach — Hackathon Brief (Terrier Cyber Quest 2026)

## 0. Problem statement (verbatim ask)

Build cyber-reasoning system: LLM + fuzzers + static/dynamic analysis + regression
harness. Must autonomously **find** vuln, **patch** it, **prove** fix holds.
Pitched to run against Armed Forces infra. Scored on: **resource utilisation,
novelty, how lightweight**. Submission = 5-slide PPT + PoC.

---

## 1. What we built — plain terms

A pipeline, not a chatbot. Feed it C/C++ code. It:

1. **Finds** bug two ways — Semgrep (static, instant) + libFuzzer/AFL++ (dynamic,
   coverage-guided, ASan/UBSan-instrumented).
2. **Locates** it from the crash's own stack trace (no hint given) — triage engine
   replays crash, parses sanitizer report, maps to CWE.
3. **Understands** it — Tree-sitter pulls the actual function + every struct/typedef
   it touches, so the model isn't guessing at types it can't see.
4. **Patches** it — 3 LLM agents (Alpha/Beta/Gamma) run in parallel, different
   strategies (analyst / minimalist / SARIF-fixer). Smallest patch that survives wins.
5. **Proves** it — DRV loop: apply → build under sanitizers → replay the *exact*
   crashing input against the *patched* binary → regression → re-scan. 5 gates,
   all must pass, `SKIPPED` never counted as a pass.
6. **Attacks its own fix** — re-fuzzes the patch, diffs behavior against the
   original on benign inputs, throws bypass-encoding payloads at it. A patch that
   only gamed the gates (`if (size==4) return;` or a silent early-return) gets
   caught and rejected here.
7. **Remembers** — but only gate-proven fixes get written to memory. No
   hallucinated self-reflection stored as fact.

## 2. Why built this way

| Design choice | Why |
|---|---|
| Prove via rebuild + replay, not LLM self-report | An LLM saying "fixed" is not evidence. A sanitizer trapping the same input on a freshly compiled binary is. |
| Hardening phase (re-fuzz + differential + evasion) | Naive automated repair is gameable — model optimizing for green CI will produce overfit or gutted patches. This is the actual novel contribution: most LLM-patch tools stop at "gates passed." |
| Tree-sitter context, not raw text window | C/C++ patches fail without struct/typedef visibility — this is the #1 cause of non-compiling AI patches. |
| Multi-agent ensemble, not one shot | Different bug classes want different fix shapes (bounds check vs. sanitize vs. API swap). Running 3 in parallel + picking smallest verified patch beats iterating one agent. |
| `gpt-4o-mini` everywhere | Directly targets the "lightweight / resource utilisation" scoring axis — $0.05 for 37 targets, not a frontier model bill. |
| Self-gating (Driller/angr) | Rather than hide platform limits, the system detects when a technique (concolic execution) can't be trusted on this host and turns itself off with a logged reason. Judges reward honesty over inflated claims. |
| `SKIPPED` ≠ pass, pre-flighted PoVs | Directly defensible under jury scrutiny — every number in `benchmark.md` is real, not asserted. |

## 3. Measured state today

37 targets, 100% gate-pass, 21/21 PoV-proven where a PoV was possible, 34/34
survived hardening, **$0.0521 total cost**, 794s wall time, 71 unit tests
(0 API calls). Full breakdown: [`benchmark.md`](benchmark.md).

Known gaps (honest, not hidden): concolic engine self-disables on arm64 macOS;
16/37 targets have no runtime-provable exploit on this platform (documented
per-target reason, not swept under the rug); AFL++ campaign not in the headline
run (verified separately to find crashes).

---

## 4. Plan to win — mapped to the 3 scoring axes

### Axis: Novelty
Current strongest card is **Phase 6 Hardening** (adversarial re-fuzz +
differential + evasion battery) — very few CRS demos (even DARPA AIxCC entrants)
show *falsification* of their own patches. Lean on this hard in the pitch.

To sharpen further before the deadline:
- [ ] **Add a "cheat detector" leaderboard slide**: show N deliberately-cheating
  patches (overfit / gutted / bypassable) fed into the system, and it catching
  100% of them. This is a demo a jury can *see* work, not just read a claim.
- [ ] **CWE-to-defense-domain mapping**: since this targets Armed Forces infra,
  add a short table connecting CWE classes found → real-world defense-relevant
  systems (embedded comms parsers, sensor firmware, C2 protocol handlers). Makes
  novelty land as "relevant to *this* buyer," not generic.
- [ ] Consider one **memory-driven speed-up demo**: same CWE fixed twice, second
  time faster/cheaper because semantic memory recalled the pattern. Quantifiable,
  visual, and it's already built (`--memory` flag) — just needs a clean run + chart.

### Axis: Lightweight / resource utilisation
Already strong (`gpt-4o-mini`, $0.05/37 targets, no GPU, runs on a laptop). To make
this land in a 5-slide deck:
- [ ] One slide-ready chart: cost & wall-time per target, and peak RSS (1.36GB).
  Numbers already measured — just needs a chart, not more work.
- [ ] Explicitly state "no fine-tuning, no local model hosting, no dedicated
  hardware" — matters for judging against solutions requiring GPU clusters.
- [ ] If time allows: try `gpt-4o-mini`-only budget vs. one frontier-model run,
  show the delta is small — proves you didn't need the expensive model.

### Axis: Resource utilisation (infra footprint / deployability)
- [ ] Document minimum footprint to run on **air-gapped or constrained networks**
  — likely question from Armed Forces evaluators. What's the offline story? (Semgrep
  rules can be vendored; fuzzing/build are fully local; only LLM calls need network —
  flag this as the one external dependency and note it can point at an on-prem/
  local LLM endpoint via the OpenAI-compatible client already in `llm_client.py`.)
- [ ] Add a note/section on running against **their own infra** per the problem
  statement's `--target` flag (`README.md` already documents this) — make explicit
  in the deck that this isn't a fixed benchmark toy, it's pointed at arbitrary
  `build-cmd`/`pov-cmd`/`test-cmd`.

### Cross-cutting, before the pitch
- [ ] Re-run full benchmark once more close to submission date, refresh
  `benchmark.md` numbers so nothing in the deck is stale.
- [ ] Fix the "Not Measured" items where cheap: patch-size diffing (already scoped
  as an easy fix in `benchmark.md` §7), CPU utilisation sampling.
- [ ] Prepare the PoC to run live or as a captured terminal recording — jury said
  "Proof-of-Concept to be submitted," so a runnable demo (not just slides) likely
  scores higher than slides alone.
- [ ] Build the actual 5-slide deck now that this doc has the material:
  - Slide 1: problem + one-line pitch ("proves the fix, doesn't just claim it")
  - Slide 2: the 6-step pipeline (§1 above) as a flow
  - Slide 3: architecture diagram (already in `architecture.md`, reuse it) + stack table
  - Slide 4: Hardening/falsification as the novelty headline + cheat-catch demo
  - Slide 5: measured numbers (37/37, $0.05, 794s) + roadmap to Armed Forces infra

---

## 5. Immediate next actions (this week)

1. Cheat-detector demo run + chart (biggest bang for novelty slide).
2. Cost/time/RSS chart from existing `benchmark.md` data (no new work, just viz).
3. One paragraph + diagram on offline/air-gapped operation story.
4. Draft the 5 slides using this doc as source text.
5. Re-run `python benchmark.py --suite all --fuzz --harden --memory --fuzz-seconds 30`
   right before submission to lock in fresh numbers.
