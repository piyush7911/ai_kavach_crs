# Benchmark — reproducible discovery scoring

`python -m benchmarks.bench --target vampi --runs 3` scores our dynamic discovery against an answer
key (`benchmarks/labels/vampi.json`) and emits the metrics a jury can check. Metrics shape adapted from
bug-hunter (MIT, © codexstar69); meaning reframed for a runtime-confirmed finder.

## VAmPI result (3 runs)

| metric | value | what it means |
|---|---|---|
| recall | **1.0** | found all 7 in-scope (dynamically reachable) bugs |
| precision | **1.0** | no false positives — every finding has a replayed exploit behind it |
| F1 | **1.0** | — |
| severity-weighted recall | **1.0** | including every critical/high |
| stability (Jaccard, 3 runs) | **1.0** | identical findings every run — not flaky |
| median run time | **2.8 s** | whole-app discovery |
| seconds / bug | **0.4 s** | — |
| model cost | **$0** | discovery is deterministic + model-free |
| out of scope | 2 RoE-excluded (live-DoS), 1 static-only (weak JWT) | scored separately, never counted against recall |

Raw: `reports/bench_vampi.json`.

## Why these numbers are honest

- **Precision ≈ 1 by construction.** A finding is only emitted after a replayed HTTP exploit confirms
  it, so there are no "plausible but unreachable" claims to deflate it. That is the whole point of a
  runtime verifier vs a static reviewer — and the number reflects it rather than inflating it.
- **Recall is over IN-SCOPE labels only.** ReDoS and rate-limiting (a live proof is a denial of service,
  forbidden by the RoE) and the weak-JWT key (a static-only find) are reported separately. Counting them
  against recall would punish us for following the rules; excluding them silently would be dishonest, so
  they are named.
- **Stability is the autonomous-run metric.** 1.0 across runs means the finder is deterministic — a
  jury running it twice gets the same result. A flaky finder scores high once and fails the demo.

## Maps to the four jury parameters

- **Autonomous bug discovery** → recall 1.0, 7/7, model-free, 2.8 s.
- **Automated patch generation** → see `reports/model_comparison.md` (nemotron 5/6 VAmPI, 4/5 NodeGoat).
- **Regression proof** → every patch gated by exploit-replay + flaky-tolerant regression + hardening.
- **Scalability / reliability** → stability 1.0, sub-second per bug, spec-free discovery on an unknown app.
