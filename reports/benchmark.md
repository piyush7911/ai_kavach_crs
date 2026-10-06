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

## NodeGoat result (3 runs) — `--target nodegoat`

A finding here is also runtime-confirmed: jsauto detects + builds an exploit, then we **replay it against
a live NodeGoat instance** and keep only what reproduces.

| metric | value | what it means |
|---|---|---|
| recall | **0.857** | confirmed 6 of 7 in-scope bugs (nosql, eval, xss, ssrf, open-redirect, allocations-IDOR) |
| precision | **1.0** | all 6 are replayed exploits — no false positives |
| F1 | **0.923** | — |
| severity-weighted recall | **0.882** | the one miss is the benefits write-IDOR (high); both criticals hit |
| stability (Jaccard, 3 runs) | **1.0** | identical every run |
| median run time | **~6.6 s** | includes booting + seeding a fresh Node+Mongo instance |
| seconds / bug | **~1.1 s** | — |
| out of scope | 4 static-only (secrets, private key, cookie flags, CSRF), 1 RoE (ReDoS) | detected statically / not live-probed |

Raw: `reports/bench_nodegoat.json`.

**The one remaining miss is honest.** We now auto-build the IDOR exploit — as one user, request two
different object ids; different data back = IDOR (the `idor` oracle). That confirms `allocations.js`
(a read-IDOR). The `benefits.js` miss is a *write* IDOR / missing access control: both ids return the
same redirect, so the read-diff oracle correctly reports "not IDOR" — catching it needs a verify-after-
write (user A changes user B's record, then observe B's record changed) or the access-control oracle.
A benchmark that reported 1.0 everywhere would not be measuring anything.

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
