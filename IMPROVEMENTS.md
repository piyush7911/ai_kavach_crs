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

**Our unique angle vs the field:** AIxCC-grade verification, but **air-gapped on a 7B local model**,
and we **test the verifier itself** (cheat detector). The AIxCC teams mostly used big cloud models.

## Model bake-off (measured today, NodeGoat, 3 confirmable bugs)

| Model (local, air-gapped unless noted) | eval | SSRF | open-redirect | proven+hardened |
|---|---|---|---|---|
| gemma4:e2b (chat, 2B) | yes | - | no | 1 |
| gpt-4.1-mini (cloud) | no | no | yes | 1 |
| **codegemma:7b (code, 7B)** | yes | yes | no | **2** |

CodeGemma (a code model) beat both the tiny local chat model and a frontier cloud chat model.
Finalist local model: **codegemma:7b** (non-Chinese, fits the Air). open-redirect is unresolved on
EVERY model — the one class that needs a template or sharper prompt.

## Tier 1 — biggest yield, do now

1. **Search-based repair (PSearch-style) instead of linear retry.** Our loop is 3 tries +
   rejection feedback. PSearch keeps a tree of promising partial patches, reflects, uses the gate
   result as an adaptive reward. Measured on SMALL models: Qwen-Coder-7B 79->107 fixes (+35%),
   Yi-Coder-9B 106->143. Model-agnostic and local; ~$0.06/bug. Directly attacks open-redirect.
   arxiv.org/html/2507.01827v5
2. **CWE-aware routing + mechanical templates.** Evidence: mechanical fixes beat semantic ones
   (patch size negatively correlates with success, rho=-0.331); ATLANTIS: "use the LLM to
   parameterize templates, not generate from scratch." Route: open-redirect / SQLi / XSS /
   path-traversal -> deterministic template (model fills a blank); logic bugs (IDOR, auth) -> LLM.
   Templates are a per-language yield booster ON TOP of the general LLM path, not the foundation.
3. **Kill small-model parse failures.** Ours fail at SYNTAX, not logic (opposite of big models).
   Whole-function AST splice already helps. If parse failures persist, grammar-constrained decoding
   gives 100% syntactic validity on small LLMs (cost: 3.6-8.2x latency) — apply only to the
   code-emission step. arxiv.org/pdf/2609.23742

## Tier 2 — coverage and confidence

4. **Finding/crash validation agent.** OSS-Fuzz-Gen added one and filtered 65% of spurious
   crashes. A cheap "is this finding real?" pass before spending repair budget -> higher precision.
5. **LLM-guided probe/seed generation.** Buttercup's edge was LLM-generated semantically-aware
   seeds for the fuzzer (not replacing it). Web analogue: smarter probes; closes our IDOR/XSS/CSRF
   detection gap. (Track 1 already added the boolean-differential oracle for NoSQL/SQL.)
6. **Keep ensemble diversity.** ATLANTIS: multiple diverse weak agents beat one strong one. Our
   adaptive strategy collapsed alpha/beta/gamma to a sequence; keep them genuinely different.

## Tier 3 — the real moat (stretch, needs a GPU/time)

7. **Fine-tune a small code model with OUR gates as the verifiable reward (RLVR/GRPO).** +13pp
   pass@1 on a 0.6B model, trainable on one RTX 3090. Our PoV+regression+hardening gates are a
   perfect verifiable reward. A CodeGemma trained to pass our gates = a purpose-built local patcher
   nobody at AIxCC did cheaply. The Air can't train — post-event or a borrowed GPU.
   arxiv.org/html/2605.30478v1
8. **Retrieval-augmented repair.** We already have the memory subsystem (recorded-but-unused).
   Wire it: retrieve the most similar past PROVEN fix into the prompt. Cheap, local, compounds.

## Open questions for Piyush

- Is the repair loop worth re-architecting to a search (Tier 1.1) before the event, or too risky?
- Templates: which classes do we trust to templates vs keep LLM-only? (open-redirect is the clear
  first template — unresolved on every model.)
- Ensemble: revert adaptive-sequential to diverse-parallel, or keep adaptive for cost?
- Anyone have a GPU for the RLVR experiment (Tier 3.7)?

Sources: AIxCC results (darpa.mil/news/2025/aixcc-results), Buttercup (blog.trailofbits.com
2025/08/07), ATLANTIS (arxiv 2509.14589), Why LLMs Fail (arxiv 2603.10072), PSearch (arxiv
2507.01827), RL-from-verification (arxiv 2605.30478), constrained decoding (arxiv 2609.23742),
OSS-Fuzz-Gen (emergentmind.com/topics/oss-fuzz-gen).
