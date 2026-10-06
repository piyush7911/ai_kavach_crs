# The closure / callback blind spot: diagnosis and fix (2026-10-07)

Question: can the lambda-capture problem that I said was blocking step 4 be fixed? Short answer: yes, the underlying blind spot is real and is now fixed
for the patterns I could isolate, but it was **not** what limited step 4 on VulnerableApp, and my earlier explanation of step 4 was wrong. What it did unlock
is one verified NodeGoat finding (NoSQL injection). Nothing was patched or pushed; the target sources are never modified (analysis runs on scratch copies).

## 1. Diagnosis by micro-benchmark (one pattern per function; source `taintSource()`, sink `sink(x)`)

`microbench/java/LambdaCases.java` (13 cases) and `microbench/js/cases.js` (10 cases), scored by whether a flow reaches the sink.

| Java pattern | before | after |
|---|---|---|
| direct, builder, enhanced for, stream map/collect, sink inside lambda, `Function.apply`, parameter function, list add/get | found | found |
| `list.forEach(x -> sb.append(x))` then `sb.toString()` (expression and block bodies) | **missed** | found |
| `optional.ifPresent(x -> sb.append(x))` | **missed** | found |
| `map.get(k).add(x)` then `map.get(k).get(0)` | **missed** | found |
| array element written inside a `Runnable` | missed | missed |
| **found** | **8 of 13** | **12 of 13** |

| JS pattern | base | + desugar | + callback binding |
|---|---|---|---|
| direct, for-of, sink in callback, promise `.then`, `.map().join()` | found | found | found |
| `arr.forEach(x => { out += x })`, object / array mutation in `forEach` | **missed** (3 cases) | found | found |
| result delivered through a callback (`db.findOne(q, function (err, doc) {...})`, and through a wrapper `cb(null, d)`) | **missed** (2 cases) | missed | found |
| **found** | **5 of 10** | 8 of 10 | **10 of 10** |

So the engine loses exactly: taint written into a **captured variable inside a lambda**, **element aliasing through `get()`**, and **results delivered through a function-valued parameter**.

## 2. The fixes (all deterministic, language-level lowering or call-graph edges)
- `scripts/desugar_lambdas.py`, applied to a scratch copy with identical line numbers (asserted):
  - Java and JS: `X.forEach(p -> BODY)` becomes a loop (`for (var p : X)` / `for (const p of X)`); two-parameter Map `forEach` and `Optional.ifPresent` also handled; a bare `return;` becomes `continue;`.
  - Java: `A.get(K).add(V);` also writes `V` through to `A` (`A._wt(V);`).
- `bind=true` in `scripts/joern_taint_data.sc` (adds call-graph edges):
  - a call `cb(...)` through a function-valued parameter, or a local variable holding a function literal, is linked to the function literals passed for that parameter (through up to 3 pass-through levels);
  - a call `obj.m(...)` that the JS front end links only to an external placeholder `Ctor:m` is linked to the internal method assigned as `this.m = ...` in that constructor, or, if the constructor is a function expression, to the same-file method with that alias.
- Step 4 now treats the parameters of consumer callbacks bound to a read call as the stored data (`second_order` block).
- New framework-check kind `property_sink`: a value assigned to MongoDB's `$where` / `$function` / `$accumulator` (JavaScript-executing operators) is a NoSQL injection sink.

## 3. Results on the real apps

| App | before | after | what changed |
|---|---|---|---|
| NodeGoat (5 taint labels, sink must be in the labelled file) | 3 (eval, ssrf, open redirect) | **4** (+ NoSQL injection) | flows `req.query` -> route call -> `AllocationsDAO.getByUserIdAndThreshold` -> `$where` string; the front end had linked that call only to an external placeholder. XSS still missed. |
| VulnerableApp (75 vulnerable / 38 secure taint-scope levels) | 48 found / 14 flagged | 48 / 14 | 7 lambda statements rewritten; no score change |
| VAmPI | SQL injection found | same | no change |

## 4. Corrections to what I said earlier
1. **Step 4's failure on VulnerableApp was not lambda capture.** After desugaring, step 4 still adds nothing. In the dedicated persistent-XSS file every level (vulnerable and secure) is flagged first-order, and still is when I rename the loop variable (so it is not a name coincidence): the engine's default handling of external calls already treats the repository object as tainted once a tainted value is saved into it, which approximates the second-order flow. My explanation in `STEPS_1_5_RESULTS.md` ("flows lost inside a lambda that mutates a captured variable") is withdrawn for this app.
2. **The "persistent XSS 8 of 13" gap was misattributed.** The 5 missed persistent-XSS instances are file-upload levels (stored uploaded content), not the database pattern I blamed.
3. **An apparent NodeGoat XSS "find" was spurious.** The matching flow ended at `usersCol.findOne(...)` in `user-dao.js`, which an LLM-proposed spec had wrongly labelled an XSS sink; the old scorer accepted a match on the source file. NodeGoat scoring now requires the sink to be in the labelled file. Under that rule the earlier variants also find 3 of 5, not more.

## 5. Caveats
- The `property_sink` for `$where`, and the same-file fallback in instance-method resolution, were added after I had looked at NodeGoat, so the NoSQL gain is not a clean held-out result. The first is generic documented MongoDB knowledge; the second is a heuristic (same file, same method name) that can over-link.
- JS instance resolution and callback binding rely on names (unique alias per file / constructor), so they can add edges that are not real.
- The `_wt` write-through can spread taint into containers that were never mutated that way (possible extra false alarms); none appeared on VulnerableApp.
- Still unsolved: an array written inside a `Runnable`/closure (Java micro-case c12), NodeGoat XSS (cause not established: the chain goes through database writes and a render call), and the unresolved Java method references (`this::helper`), which are now skipped safely.
- Desugaring is a lowering for analysis only. It assumes the lambda runs once per element, in order.
- Re-run command sequence: `scripts/desugar_lambdas.py <src> <dest>`, build the code graph on `<dest>`, then `joern_taint_data.sc ... --param bind=true`. Final runs are `results/joern/*.final4.tsv`.
