# Research: deterministic, language-agnostic ways to find real bugs from source

Date 2026-10-06. Goal: raise recall and cut false alarms without relying on an LLM to decide what is real.
Status: research and proposal only. Nothing here is implemented or installed. Items marked (unverified) were
not tried on this machine.

## Why our numbers are low (from the benchmark runs)
1. Pattern rules match a call's shape, not whether attacker data reaches it (BenchmarkJava: 894 SQLi flags, 272 real).
2. Only 5 Python / 9 Java rules of our own; no taint tracking outside JS.
3. Logic bugs (IDOR, missing auth, CSRF) need structure, not patterns.
4. Known-vulnerable dependencies are only checked for npm.

## The layers (cheapest and most reliable first)

| # | Layer | Language-agnostic? | What it finds | Cost / licence |
|---|---|---|---|---|
| 1 | **Community rules vendored offline** (measured: Java 290 -> 1,248 of 1,415, Python +1 to +4 per app) | per-language rule files | known dangerous APIs | free; Semgrep Rules License v1.0, check before shipping |
| 2 | **Taint engine with cross-function / cross-file flow**: Opengrep (LGPL-2.1 fork of Semgrep CE, drop-in rule format, restores inter-procedural taint) | rules are per-language, engine is one | injection classes with far fewer false alarms | free. (unverified on this Mac) |
| 3 | **Code property graph (Joern, Apache-2.0)**: one graph + one taint engine for C/C++, Java, JS, Python, PHP, Go, Kotlin, Ruby, C# | yes, the most language-agnostic option | taint paths, call graph, reachability, custom queries | needs a JVM (present); heavier. (unverified) |
| 4 | **Sources / sinks / sanitizers as data files**, per framework (Flask, Django, Spring, Express...). We already do this for JS (`config/js_knowledge.json`); mine the same facts out of the community taint rules instead of hand-writing | yes (one schema) | coverage grows by adding data, not code | free |
| 5 | **Generic entry-point extraction** (route map from the framework: decorators, `urls.py`, `router.get`, Spring mappings) with tree-sitter, which we already use | yes | attack surface; feeds taint sources and the live probes | free |
| 6 | **Structural logic checks over the route map + call graph**: route reads an object id and loads it with no owner/user comparison (IDOR); state-changing route without auth decorator while siblings have one; POST without CSRF middleware; admin-looking route without role check | yes once layer 5 exists | IDOR, broken access control, CSRF: the classes we missed most (django.nv: 12 IDOR + 3 CSRF) | free; needs per-framework auth-marker data |
| 7 | **Dependency / SCA from the OSV database** (npm, PyPI, Maven, Go, ...) matched against lockfiles; we already do this offline for npm only | yes | known-CVE libraries, the largest share of real CVEs in the wild | free, snapshot vendored for offline use |
| 8 | **Config and secrets checks** (entropy + patterns, DEBUG flags, weak hashers, cookie flags, CORS `*`) as key-value rules | yes | misconfiguration, hardcoded secrets | free |
| 9 | **Constant propagation and dead-branch pruning** before reporting (BenchmarkJava's safe cases hinge on values overwritten with constants or branches that never run) | needs an IR; Joern provides one | removes the false alarms pattern rules cannot | part of layer 3 |
| 10 | **Live confirmation**: replay an exploit against the running endpoint (our existing oracle engine); mark `confirmed` only if it fires | yes (HTTP) | turns candidates into proven bugs | already built for NodeGoat/VAmPI; needs a runner per app |
| 11 | **Sanitizer-guided fuzzing**: Jazzer (Java), Jazzer.js (JS), Atheris (Python), libFuzzer/AFL++ (C/C++); Jazzer ships injection sanitizers (SQL, command, path, SSRF) | per-language tool, same idea | real crashes / injections with no false positives | free; needs a harness per target |
| 12 | **Spec-driven API fuzzing** from the route map / OpenAPI (property-based, e.g. Schemathesis) | yes | 5xx errors, schema violations, auth gaps | free |

## Where an LLM still helps (and must not decide)
IRIS (ICLR 2025) uses the LLM only to infer taint specs (sources/sinks) and to judge reported paths, with CodeQL doing
the flow analysis. Reported: CodeQL alone 27 of 120 vulnerabilities, IRIS + GPT-4 55 of 120, with a lower false-discovery
rate. Takeaway: LLM proposes specs and triages; a deterministic engine and an exploit decide. Findings that only the LLM
suggested stay `candidate`.

## What is not achievable
- "All real bugs" is impossible in general (undecidable); the honest claim is recall per supported class, measured.
- Business-logic flaws remain mostly out of reach for any automatic tool.
- CodeQL: strongest flow analysis, but the engine is proprietary and free only for open-source / research use. Fine to
  measure against, risky to build the product on.
- A tool finding nothing means "not found", not "safe".

## Proposed order (each step measured on the same benchmarks, reported as true / found / confirmed / patched)
1. Opengrep + community taint rules; target: BenchmarkJava FPR below 0.2 with TPR kept above 0.8.
2. Route-map extraction (layer 5) + structural authz/CSRF checks (layer 6); target: django.nv IDOR/CSRF.
3. OSV-based SCA for all ecosystems (layer 7); target: OSSF CVEs that are dependency issues.
4. Joern pilot on one language pair (Java + Python): taint, reachability, constant pruning.
5. Live confirmation on every app we can start; fuzzers where a harness is cheap.
6. LLM for spec inference and triage only, flagged as such.

## Sources
- Joern: https://docs.joern.io/ and the PLDI 2025 SOAP paper on language-agnostic taint tracking, https://pldi25.sigplan.org/details/SOAP-2025-papers/2/Scalable-Language-Agnostic-Taint-Tracking-Using-Explicit-Data-Dependencies
- Opengrep vs Semgrep: https://appsecsanta.com/opengrep-vs-semgrep and https://semgrep.dev/docs/faq/comparisons/opengrep
- Semgrep vs CodeQL: https://aicodereview.cc/blog/semgrep-vs-codeql
- IRIS: https://arxiv.org/abs/2405.17238
- OWASP Benchmark scoring (Youden): https://owasp.org/www-project-benchmark/
