| Metric | 20261001_183133 | 20261001_182905 |
|---|---:|---:|
| models | ['gpt-4o-mini'] | ['qwen2.5-coder:14b'] |
| targets | 3 | 3 |
| patched_all_gates | 2 | 3 |
| pass_rate | 66.7% | 100.0% |
| pov_proven | 2/3 | 3/3 |
| mean_seconds_per_target | 45.3 | 102.0 |
| usage_scope | compared targets | compared targets |
| output_tokens | 22358 | 23994 |
| output_tokens_per_wall_second | 164.5 | 78.4 |
| cost_usd | 0.029264 | 0.0 |
| unpriced_tokens | 0 | 137495 |
| peak_rss_mb_harness | 75.8 | 75.5 |

Compared over the 3 targets present in both runs.
Local runs are priced at $0 only when the model is unpriced; unpriced tokens are shown.
Peak RSS is the harness process only; a local model's own memory is reported by the model check (Ollama /api/ps), not here.

| Target | A | B | A s | B s |
|---|---|---|---:|---:|
| CVE-2019-11834-CJSON-PARSE-STRING | unresolved | patched | 74.59 | 183.51 |
| CVE-2019-11835-CJSON-MINIFY | patched | patched | 9.04 | 41.67 |
| GH800-CJSON-PARSE-OBJECT-OOB | patched | patched | 52.28 | 80.83 |
