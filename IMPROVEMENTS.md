# Improvement roadmap — ideas from the field (2026-10-06)

Grounded in recent public work closest to what we're building: the DARPA AIxCC 2025 finals
(autonomous find-and-patch, same problem), the LLM-repair literature, and small-model papers.
For discussion — add your view inline.

## What the field confirms (keep doing)

Every AIxCC winner is **verify-first**. Buttercup "never submitted patches without PoVs"; the
scoring **penalised false positives**; ATLANTIS's own lesson is "validation is everything." The
"Why LLMs Fail" study: even GPT-class models get only **24.8% of security patches fully correct**,
**51% are insecure-and-breaking**. So raw LLM patches are untrustworthy — our gates are the
consensus winning design, not a nice-to-have.

**Our unique angle vs the field:** AIxCC-grade verification, but **runs locally on a 7B model** (we
state what the sandbox denies and show the test, not "air-gapped"), and we **test the verifier
itself** (cheat detector). The AIxCC teams mostly used big cloud models.

## Model bake-off (measured, NodeGoat, 3 confirmable bugs)

| Model | eval | SSRF | open-redirect | proven+hardened |
|---|---|---|---|---|
| gemma4:e2b (local chat, 2B) | yes | - | no | 1 |
| codegemma:7b (local code, 7B) | yes | yes | no | 2 |
| gpt-4.1-mini (cloud) | not run | not run | **yes (25 s)** | 1 (of 1 run) |

CodeGemma (a code model) beat the tiny local chat model and is the finalist local model (non-Chinese,
fits the Air). **open-redirect is solvable** — gpt-4.1-mini proved+hardened it in 25 s — but the weak
LOCAL models fail it, so it is the clearest candidate for a deterministic template (Tier 1.2). The
gpt-4.1-mini eval/SSRF cells are "not run", not failures.

## Tier 1 — biggest yield, do now

> NOTE (Piyush): several arXiv ids below encode 2026 dates and are UNVERIFIED. Treat every quoted
> number (24.8%, +35%, +13pp, rho=-0.331, 3.6-8.2x) as unchecked until someone opens the paper.

1. **Search-based repair (PSearch-style) instead of linear retry.** Our loop is 3 tries +
   rejection feedback. PSearch keeps a tree of promising partial patches, reflects, uses the gate
   result as an adaptive reward. Reported (UNVERIFIED) gains on small models: Qwen-Coder-7B +35%.
   Model-agnostic and local. Directly attacks open-redirect. arxiv 2507.01827 (verify)
2. **CWE-aware routing + mechanical templates.** Piyush has started `src/jsauto/templates.py`.
   Reported evidence (UNVERIFIED): mechanical fixes beat semantic ones; ATLANTIS: "parameterize
   templates, not generate from scratch." Route: open-redirect / SQLi / XSS / path-traversal ->
   template; logic bugs (IDOR, auth) -> LLM. **Catch (measured): a template is NOT trusted more
   than a model patch — it must pass the SAME gates, including a regression that actually exercises
   the feature.** Track 1 just added a `/learn?url=/tutorial` regression flow: a gutted open-redirect
   fix (always -> /dashboard) now FAILS regression where before it passed. Templates are a
   per-language yield booster ON TOP of the general LLM path, not the foundation.
3. **Kill small-model parse failures.** Ours fail at SYNTAX, not logic. Whole-function AST splice
   already helps. If parse failures persist, grammar-constrained decoding reportedly gives high
   syntactic validity on small LLMs at a latency cost — apply only to the code-emission step.
   arxiv 2609.23742 (verify)

## Tier 2 — coverage and confidence

4. **Finding/crash validation agent.** OSS-Fuzz-Gen added one and filtered 65% of spurious
   crashes. A cheap "is this finding real?" pass before spending repair budget -> higher precision.
5. **Detection gap is CLOSED (Piyush): IDOR, XSS, CSRF now detected with general rules, 12/12 on
   NodeGoat.** What's LEFT is *confirming* IDOR and CSRF — they have no probe oracle yet. Track 1
   added the boolean-differential oracle for NoSQL/SQL; IDOR needs two-user authorization probing,
   CSRF needs a tokenless-POST / foreign-Origin probe. (Still worth: LLM-guided probe payloads.)
6. **Ensemble diversity — RESOLVED, no change.** The adaptive ladder already runs alpha/beta/gamma
   as genuinely different prompts, just sequentially. Parallel diversity costs more model calls and
   the model is the bottleneck on this Mac. Keep adaptive.

## Tier 3 — the real moat (stretch, needs a GPU/time)

7. **Fine-tune a small code model with OUR gates as the verifiable reward (RLVR/GRPO).** +13pp
   pass@1 on a 0.6B model, trainable on one RTX 3090. Our PoV+regression+hardening gates are a
   perfect verifiable reward. A CodeGemma trained to pass our gates = a purpose-built local patcher
   nobody at AIxCC did cheaply. The Air can't train — post-event or a borrowed GPU.
   arxiv.org/html/2605.30478v1
8. **Retrieval-augmented repair.** We already have the memory subsystem (recorded-but-unused).
   Wire it: retrieve the most similar past PROVEN fix into the prompt. Cheap, local, compounds.

## Open questions (updated after Piyush's review)

- **Search vs linear repair (Tier 1.1):** worth re-architecting before the event, or too risky? Still open.
- **Templates:** open-redirect is the clear first (weak local models all fail it; gpt-4.1-mini proves
  it). Agreed a template must pass the same gates; the regression that catches a gutted redirect is
  now in place. Which classes next — SQLi, XSS, path-traversal?
- **Confirm IDOR/CSRF:** add the two missing probe oracles (two-user auth; tokenless-POST)?
- **GPU for the RLVR experiment (Tier 3.7)?** Still open.
- ~~Ensemble parallel vs sequential~~ — resolved: keep adaptive (model is the bottleneck).

Corrections applied from Piyush's review: dropped "air-gapped" wording; fixed the bake-off table
(open-redirect IS solvable; gpt-4.1-mini eval/SSRF not run); flagged the arXiv ids/numbers as
unverified; detection gap marked closed.

Sources: AIxCC results (darpa.mil/news/2025/aixcc-results), Buttercup (blog.trailofbits.com
2025/08/07), ATLANTIS (arxiv 2509.14589), Why LLMs Fail (arxiv 2603.10072), PSearch (arxiv
2507.01827), RL-from-verification (arxiv 2605.30478), constrained decoding (arxiv 2609.23742),
OSS-Fuzz-Gen (emergentmind.com/topics/oss-fuzz-gen).
