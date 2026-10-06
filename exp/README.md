# exp/ — public benchmark experiments (2026-10-06)

Everything produced while benchmarking Kavach on public vulnerable-app / CVE benchmarks lives here.
Nothing in `src/` or `config/` was modified. Nothing was pushed to GitHub.

## Layout

| Path | What |
|---|---|
| `scripts/score_app.py` | scores findings against a hand-built answer key (apps) |
| `scripts/score_owasp_java.py` | OWASP Benchmark scoring (TPR / FPR / Youden per category) |
| `scripts/ossf_run.py` | OpenSSF CVE Benchmark runner (pre-patch vs post-patch commits) |
| `scripts/community_python.py`, `community_java.py` | measure community Semgrep rules without changing Kavach |
| `labels/*.json` | answer keys (true bugs) with their source: README, author comments, or my own audit |
| `results/` | raw findings + scores, baseline in `results/*.findings.json`, community rules in `results/community/` |
| `third_party/semgrep-rules/` | clone of semgrep/semgrep-rules (git-ignored; Semgrep Rules License v1.0, check before shipping) |

The cloned benchmark repos stay in `benchmark_workspace/public/` (about 600 MB, not copied here).

Run from `ai_kavach_crs/` with the conda env python, e.g. `python -m exp.scripts.score_app dvna exp/results/dvna.findings.json`.

## Baseline: Kavach unmodified

"Fixed" is 0 everywhere: there is no patch step for scan-only findings (the repair loops need a live app + runner, only NodeGoat has one).

| Benchmark | True bugs | Found | Fixed |
|---|---|---|---|
| DVFA | 5 | 2 | 0 |
| breakableflask | 8 | 2 | 0 |
| django.nv | 27 | 3 | 0 |
| vulnerable-django-app | 7 | 3 | 0 |
| DVNA | 11 | 9 | 0 |
| Juice Shop (23 labelled code-level bugs, a slice of its 100+ challenges) | 23 | 11 | 0 |
| OWASP BenchmarkJava | 1,415 real | 290 (FPR 19.4% on 1,325 safe tests, Youden 0.011) | 0 |
| OSSF CVE Benchmark | 231 weaknesses in 221 scanned CVEs (2 could not be fetched) | 10 | 0 (the finding disappears on the post-patch commit for 4 of them) |

Bugs found: see `results/*.findings.json`; found/missed lists are printed by `score_app.py`.
OSSF CVEs detected: CVE-2018-16478, CVE-2017-16029, CVE-2017-16084, CVE-2018-3733 (path traversal), CVE-2018-3726, CVE-2017-18353, CVE-2019-10765 (reflected output), CVE-2020-8205, CVE-2020-8135 (SSRF), CVE-2019-10758 (eval injection).

## Experiment: community Semgrep rules (python/ and java/ from semgrep-rules), measured only

| Benchmark | True bugs | Baseline found | Community found | Union | Community findings not in answer key |
|---|---|---|---|---|---|
| DVFA | 5 | 2 | 2 | 3 | 4 |
| breakableflask | 8 | 2 | 4 | 4 | 34 |
| django.nv | 27 | 3 | 7 | 8 | 29 |
| vulnerable-django-app | 7 | 3 | 4 | 5 | 9 |

"Not in answer key" is not the same as false positive: many are real but unlabelled, and some are style rules. Not triaged by hand.

BenchmarkJava with the community Java rules (23 s run):

| | Baseline | Community |
|---|---|---|
| True bugs found | 290 / 1,415 | 1,248 / 1,415 (TPR 0.882) |
| Safe tests flagged | 257 / 1,325 | 552 / 1,325 (FPR 0.417) |
| Youden (TPR - FPR) | 0.011 | 0.465 |
| Categories covered | 3 of 11 | 11 of 11 |

Crypto, secure cookie and weak random reach TPR 1.0 with FPR 0. SQLi (FPR 0.73), command injection (0.87), path traversal (0.79) and LDAP stay noisy: these rules match the pattern and do not track data flow, so safe variants are flagged too.

## Not run
- SecJS: ships no dataset (builder code only).
- CVE-Bench (uiuc-kang-lab/cve-bench): needs Docker, not installed.
- vulnerable-node-api: repo does not exist; dvws-node and vulnerable-node are cloned as stand-ins but not yet scanned.
- Juliet Java: downloaded (46,793 files), not scanned yet. C/C++ Juliet link is dead.

## Caveats
- Answer keys for the apps were built by me from each repo's docs and source. Provenance is in each label (`source`).
- The OSSF match is "a finding on the weakness file within 5 lines, or inside the same function". The post-patch "cleared" count only means the same finding no longer fires.
- Community-rule numbers were not tuned on the benchmark answers.
- `results/nodegoat.findings.json` was regenerated (plain `src.jsauto --no-deps`) after I deleted a same-named file by mistake; the original may have used other flags.
- Installed `tree-sitter-python` and `tree-sitter-java` into the conda env (needed by existing code); not yet logged in INSTALLED.md.
