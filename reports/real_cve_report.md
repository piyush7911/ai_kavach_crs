# Real-CVE Suite Report

Published CVEs in **unmodified upstream source**. Each tree is checked out
at the commit immediately before the security fix landed.

**Passed all gates:** 3/3 · **PoV-proven:** 3/3 · **Survived hardening:** 3/3

| CVE | CWE | Status | Agent | Hardening | Pre-flight |
| :-- | :-- | :----- | :---- | :-------- | :--------- |
| CVE-2019-11835-CJSON-MINIFY | CWE-125 | **PATCHED** | beta | SURVIVED | PoV reproduces on the original; gate is valid |
| CVE-2019-11834-CJSON-PARSE-STRING | CWE-125 | **PATCHED** | gamma | SURVIVED | PoV reproduces on the original; gate is valid |
| GH800-CJSON-PARSE-OBJECT-OOB | CWE-125 | **PATCHED** | alpha | SURVIVED | PoV reproduces on the original; gate is valid |
