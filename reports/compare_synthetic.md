| Metric | 20261001_170218 | 20261001_183618 |
|---|---:|---:|
| models | ['gpt-4o-mini'] | ['qwen2.5-coder:14b'] |
| targets | 10 | 10 |
| patched_all_gates | 10 | 9 |
| pass_rate | 100.0% | 90.0% |
| pov_proven | 7/7 | 6/7 |
| mean_seconds_per_target | 7.4 | 15.2 |
| usage_scope | compared targets | compared targets |
| output_tokens | 9864 | 12099 |
| output_tokens_per_wall_second | 133.2 | 79.4 |
| cost_usd | 0.010081 | 0.0 |
| unpriced_tokens | 0 | 57909 |
| peak_rss_mb_harness | 1910.2 | 2094.9 |

Compared over the 10 targets present in both runs.
Local runs are priced at $0 only when the model is unpriced; unpriced tokens are shown.
Peak RSS is the harness process only; a local model's own memory is reported by the model check (Ollama /api/ps), not here.

| Target | A | B | A s | B s |
|---|---|---|---:|---:|
| SYN-01-MAGIC-BYTES | patched | patched | 8.54 | 27.01 |
| SYN-02-DEEP-TYPEDEF | patched | patched | 6.13 | 7.26 |
| SYN-03-INT-OVERFLOW | patched | patched | 6.82 | 8.1 |
| SYN-04-TRUNCATION | patched | patched | 5.9 | 9.88 |
| SYN-05-DOUBLE-FREE | patched | unresolved_hardening | 4.91 | 7.25 |
| SYN-06-OFF-BY-ONE | patched | patched | 17.45 | 11.52 |
| SYN-07-FORMAT-STRING | patched | patched | 4.0 | 6.92 |
| SYN-08-PATH-TRAVERSAL | patched | patched | 9.28 | 17.53 |
| SYN-09-CMD-INJECTION | patched | patched | 6.38 | 49.61 |
| SYN-10-NULL-DEREF | patched | patched | 4.63 | 7.37 |
