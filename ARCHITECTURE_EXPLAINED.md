# AI Kavach CRS: How It Works (Plain-Language Report)

*Written from the source code, not from the older markdown docs. Where the docs and the code disagree, the code wins and I say so.*

---

## 1. The one-minute story

We built a robot security engineer. You give it an application it has never seen. It does four things:

1. **FIND**: it looks for bugs.
2. **PROVE**: it builds a real attack (an "exploit") and fires it at the running app. If the attack works, the bug is real.
3. **PATCH**: it asks an AI model to rewrite the broken function.
4. **VERIFY**: it checks the patch with strict, non-AI tests: the attack must now fail, the app must still work, and other versions of the attack must also fail.

**The most important idea: we never trust the AI.** The AI only *suggests* a patch. Plain code, not AI, decides if the patch is accepted. A weak AI therefore gives a lower success rate, but not unsafe patches.

A patch is only called **`proven`** when the attack worked before the patch, fails after it, and the app still behaves normally.

---

## 2. The big picture

```
 Source code of target app
        |
        v
 [1] FIND      static scan + flow analysis + dependency audit   (no AI needed to flag candidates)
        |
        v
 [2] CONFIRM   build an exploit, run it on the ORIGINAL app
        |       works?  -> real bug.   doesn't work? -> drop the proof, can never be "proven"
        v
 [3] PATCH     AI rewrites ONLY the flagged function
        |
        v
 [4] GATES     compiles/starts?  attack blocked?  app still works?  attack variants blocked?
        |       any gate fails -> the reason goes back to the AI, it tries again
        v
 [5] RESULT    proven / patched_unproven / unresolved   + diff + evidence file
```

There is one shared design and **three language back-ends**:

| Back-end | Folder | Target |
|---|---|---|
| **Node.js / JavaScript** | `src/jsauto/` | Express-style web apps (tested on NodeGoat) |
| **Python** | `src/pyauto/` | Flask-style web apps (tested on VAmPI) |
| **C / C++** | `src/autonomy/`, `src/analysis_engine/`, `src/patch_validator/` | libraries, found by fuzzing (tested on cJSON) |

The "prove it over HTTP" machinery is shared by Node and Python because it only speaks HTTP and doesn't care what language the app is written in.

---

## 3. Node.js: step by step

### 3.1 Finding bugs (identify)

Three detectors run and their results are merged into one list of "findings" (one per bug).

1. **Semgrep rules** (`src/jsauto/static.py`). Pattern rules shipped as local files (about 233 public rules plus a few of ours). Nothing is downloaded at run time.
2. **Flow analysis** (`src/jsauto/flow.py`, the biggest file at ~900 lines). This is our own "follow the user's data" engine:
   - It finds **entry points**: functions registered on a route (`app.get("/x", handler)`) or that read things like `.query` / `.body` from one of their parameters. It does not look for the name `req`, so renaming it changes nothing.
   - It follows the user's data through variables, templates and function calls, **across files**.
   - It stops following when it sees a cleaner (`parseInt`, `encodeURIComponent`).
   - If the data reaches a dangerous call (**sink**: `eval`, a DB query, an HTTP request, `res.redirect`), that is a candidate bug.
   - Calls it does not recognise go to the AI to classify. The answer is cached. If the AI is down, that is reported, never hidden.
3. **Dependency audit** (`src/jsauto/deps.py`, `advisories.py`). Compares `package-lock.json` against a **local snapshot** of known vulnerabilities (7,216 advisories). It works offline because the rules forbid using the npm registry.

It also has structural rules for XSS in templates (`templates.py`), IDOR (using an id from the request with no owner check) and missing CSRF protection.

Secrets in test or seed files are marked `informational`, not bugs. A committed private key is never downgraded.

### 3.2 Proving the bug (prove)

`src/jsauto/probes.py` **describes** an attack as a small JSON object: method, path, body, who to log in as, and a **success check** (the oracle). It does not send anything itself. A separate runner sends it to a copy of the app running on **localhost only**.

Rules that make the proof trustworthy:

- **Send every field the handler reads.** Benign values for all except the one carrying the payload. Otherwise the app rejects the request for being incomplete, which looks like "not vulnerable".
- **Use a marker that can't be faked.** For eval injection we send `7*3` and look for a standalone `21`. Merely echoing our input back cannot fake that.
- **Control request.** The same request with a harmless value is also sent. If the success check also fires on the harmless one, the oracle is broken, so the exploit is not trusted (`control_matched` in the evidence).
- **Variants.** Other spellings of the same attack (different encoding, `//evil.com` instead of `https://evil.com`). Only variants that *work on the unpatched app* are kept. A variant that never worked would "pass" any patch and prove nothing.

Attack types the code can build (from `config/js_probes.json`): open-redirect, eval-injection, command-injection, path-traversal, SSRF, reflected output, XSS (HTML and URL-start), NoSQL injection, SQL injection.

Listed in the code as **unsupported** (no probe built): ReDoS, deserialization, hard-coded secret, private key, vulnerable dependency, insecure session cookie, most XSS contexts, **IDOR and missing CSRF**. These are repaired *without* the attack check, so they can never be `proven`.

The runner side (`benchmarks/nodegoat/`) starts the app on its own port with its own throwaway Mongo database, loopback only, throttled. It also holds the attack files (`povs/`) and **13 regression flows** (`flows.json`).

### 3.3 Patching (patch)

The patch loop is in `src/jsauto/repair.py`. For each finding:

1. The AI is shown **one function** (not the whole file), the route, the fix advice for that bug class, and the path the data took.
2. Its answer **replaces that function by syntax-tree position** (`patch.py`). It must parse as valid JavaScript.
3. **Patch policy** (`check_patch` in `patch.py`) rejects the patch if it:
   - edits a test file;
   - changes more than 80 lines;
   - touches anything outside the flagged function (new `require`/`import` at the top is allowed);
   - **adds** `eval`, `Function`, shell execution, outbound network calls, an empty `catch`, a time-based `if`, disabled TLS, `process.exit`, or a listener;
   - empties the function (statement count drops below a third).
4. **Three agents, escalating** ("adaptive" strategy). **Alpha** (analyst) tries first. If that fails, **Beta** (smallest possible change) is told what Alpha tried and why it failed. If that fails, **Gamma** (standard remediation) runs on a stronger model if one is declared and the key can really call it. An identical repeated answer stops that tier early, since the same input would give the same rejection.
5. Dependency bugs are fixed **without AI**: raise the version to the published fix. A major version bump is left to a human. The result is only `patched_unproven` because packages were not reinstalled.
6. A private key in the repo is reported as **not fixable by a code edit** (remove it and rotate it).

### 3.4 The gates (verify / regression)

Run in order by `_run_gates` in `repair.py`. The first failure stops the run and its reason goes back to the AI.

| # | Gate | Question | Pass means |
|---|---|---|---|
| 1 | **start** | Does the patched app start healthy? | yes |
| 2 | **pov** (proof of vulnerability) | Replay the original exploit | it no longer works |
| 3 | **regression** | Run the app's normal flows (login, profile, contributions, and so on) | all still pass |
| 4 | **hardening** | Replay every attack variant | none work |

Every gate is **tri-state: pass / fail / skipped**. A skipped gate is **never** counted as a pass. No exploit means pov is `skipped`, so the best possible result is `patched_unproven`.

Final labels:

- **`proven`**: pov and regression both passed (and `hardened` is true if variants also passed).
- **`patched_unproven`**: nothing failed, but something was skipped.
- **`unresolved`**: no attempt passed.
- **`not_a_code_fix`**, **`already_fixed`** (an earlier patch fixed it too), **`error`**.

### 3.5 The `fix` command (the whole cycle)

`python -m src.jsauto.fix --target DIR --runner <runner module>` (`src/jsauto/fix.py`):

1. Scan, then sort findings by severity.
2. For each: **confirm** on the original app, with a control request, then keep only variants that work.
3. Patches pile up on a **copy** of the app, so later fixes are made against earlier ones.
4. **Final check** on the fully patched tree: start, regression, and every confirmed exploit replayed again.
5. Output: `evidence.json` (status and reason per finding), `patches/<id>.diff`, `final.diff`.

### 3.6 Regression, in one sentence

"Regression" means *did the fix break something that used to work?* For Node it is the runner's 13 recorded flows, re-run against every candidate patch and again on the final tree. It catches lazy fixes like "always redirect to /dashboard", which blocks the attack but kills the feature.

---

## 4. Python: step by step

The Python back-end copies the same design, but **it is less finished than Node**. Here is what the code really does.

### 4.1 Finding bugs

- **Static** (`src/pyauto/static.py`): runs 5 Semgrep rules from `config/semgrep/kavach_py.yaml`: hard-coded secret, `eval`/`exec`, SQL built by string formatting, command injection, Flask `debug=True`. Each hit is mapped to its enclosing function using tree-sitter-python. It produces the same `Finding` object Node uses. There is **no Python flow analysis and no Python dependency audit**.
- **Dynamic probes** (`src/pyauto/probes.py`): logic bugs are not visible in the code text, so it attacks the running app. It reads the app's routes (from an OpenAPI file, or straight from a live Flask app's URL map, so no spec is needed) and tries five families on each route:
  1. **Data exposure**: does a response contain `password`, `token`, `secret`, and so on?
  2. **Injection**: send a "true" condition and a "false" condition. If the two responses differ, the input reaches a query.
  3. **BOLA / IDOR**: log in as user A and request user B's object.
  4. **User enumeration**: do login errors reveal whether a user exists?
  5. **Mass assignment**: register with `admin: true` and see if it sticks.
- **Probe policy** (`probe_policy.py`) skips pointless or unsafe probes and records why. It never probes DoS, ReDoS or rate limiting, because a live proof would be a denial of service, which the rules forbid.

### 4.2 Proving

It reuses the **same** HTTP exploit engine as Node (`benchmarks/oracles.py`, which is `run_exploit` and `Session`). Only an auth config is app-specific (VAmPI uses bearer-token login). Everything goes to localhost, throttled.

### 4.3 Patching and verifying

`src/pyauto/repair.py` + `patch.py` + `runner.py`:

1. The AI gets the one function plus the fix advice and must return the **whole fixed function**.
2. The function is spliced in by tree-sitter byte range, indentation-matched, then checked for syntax.
3. The **patched app is started on a free port** (`PyAppServer` in `runner.py`), seeded, and health-checked.
4. The exploit is replayed. Then optional regression flows run. A flow only counts as broken if it fails **3 out of 3 tries**, so a slow database does not reject a good patch.
5. Every rejection is fed back to the AI, up to 3 attempts.
6. Cleanup: the temp copy is deleted and the app process is killed.

### 4.4 Honest differences from Node (checked in code)

| Capability | Node | Python |
|---|---|---|
| Static rules | ~240 | 5 |
| Flow / taint analysis | yes | no |
| Dependency audit | yes | no |
| Patch **policy** gate (no `eval`, size cap, scope) | yes | **no**, only "must parse" |
| Hardening with attack variants | yes | **no** |
| Multi-agent escalation | alpha, beta, gamma | single prompt, 3 tries |
| Part of the `fix` command | yes | **no** |
| Called from the dashboard | n/a | **no** |

The Python repair loop is only **called from benchmark scripts** (`benchmarks/pyrepair_vampi.py` and similar). The exploit and regression flow there are hand-written for VAmPI. The older doc `REPAIR_HANDOFF.md` lists the missing pieces, and the code confirms they are still missing: the Python policy gate and folding into the `fix` command.

**What has actually been shown for Python:** on VAmPI's data-exposure bug (`/_debug` leaking passwords), a local `codegemma:7b` model produced a patch accepted on the first attempt (about 13 s). A mass-assignment fix was also checked in both directions (vulnerable gives 200, patched gives 401), but that fix was a reference patch written by hand, not by the model.

---

## 5. C / C++ (short version)

Used for libraries and parsers, where the proof is a **crash** rather than an HTTP request.

1. **Find**: Semgrep plus fuzzing the public parser functions.
2. **Prove**: a harness is built per function and compiled with **ASan/UBSan** sanitizers. A coverage "reach judge" checks the flagged function really ran. A fuzzer (libFuzzer/AFL++) hunts for a crash. A crash is triaged and de-duplicated.
3. **Patch**: the same alpha, beta, gamma agents and a critic ("delta") who reads a failed gate and gives one instruction but writes no code.
4. **Verify**: policy (`src/patch_validator/policy.py`), rebuild under sanitizers, replay all crashes, and a **behaviour oracle** recorded from the original program for regression.
5. **Harden** (`hardening.py`): re-fuzz the patched build and compare it with the original on many inputs (**differential testing**). Bounded model checking (CBMC) is also available on a few synthetic targets.

Result labels: `proven`, `falsified` (hardening broke the patch), `unresolved`, `not_reached`, `no_crash`. Note that `no_crash` means "we found nothing", not "it's safe".

---

## 6. Safety rules built into the system

- **Sandbox** (`src/patch_validator/sandbox.py`): commands run with network denied and writes limited to the workspace. On macOS it uses `sandbox-exec`, on Linux `bwrap`. In `required` mode, no sandbox means the command does not run.
- **Loopback only**: the Node runner forces every listener onto 127.0.0.1 from outside the target tree, so a patch cannot undo it.
- **Audit trail**: every model call goes through one choke point and is logged (`KAVACH_LLM_TRACE`): prompt, response, model, tokens, errors.
- **Endpoint and model pinning**: `KAVACH_ALLOWED_ENDPOINTS` and `KAVACH_ALLOWED_MODELS` refuse any undeclared endpoint or model.
- **Prompt-injection scrub** (`src/context_engine/injection_scrub.py`): comments in the target's source that look like instructions to an AI are replaced before any prompt is built.
- **No registry access**: the dependency data is vendored and the Semgrep rules are local files.

---

## 7. Why we think it generalises to an unseen app

- Detection looks for **roles and shapes** (a function that reads `.query` off a parameter), not names like `req`.
- Knowledge about dangerous APIs and fix advice lives in **data files** (`config/js_knowledge.json`, `js_probes.json`, `js_fix_guidance.json`), not in code.
- **Rename tests** rewrite every name in an app and require identical detection. They found a real bug.
- A **name tripwire** fails the build if engine code mentions the benchmark app.
- NodeGoat's own fixes ship as code comments. A test with **all comments stripped** (41 files) kept all 4 proven fixes. The model reasons the fix; it does not copy the answer.

---

## 8. Results we can cite (and how much to trust each)

*These numbers come from our own report files, not from code I could re-run here, so treat them as "claimed in the project's records".*

| Result | Number | Confidence |
|---|---|---|
| Node: NodeGoat detection | 12 of 12 known bugs found, precision 0.92 | Measured on the app we developed against |
| Node: NodeGoat full cycle with local `codegemma:7b` | 4 of 5 confirmable bugs proven and hardened (eval, NoSQL, SSRF, XSS); open-redirect unresolved | One live run |
| Node: unseen app (DVNA) | 6 of 6 core injection classes with the model classifying unknown calls | One run, no tuning |
| Python: VAmPI | static found 4; data-exposure fix proven by local model on attempt 1 | One bug, one run |
| C: 44-target benchmark | 44/44 passed gates (older sweep, not re-run on current code) | Older code |
| C: real CVE | cJSON CVE-2019-11835 found and patched with no hand-written proof, 4 of 5 runs | Small n |

---

## 9. What is NOT proven (say this out loud, it builds trust)

- **`proven` is not a formal proof.** It means the exploit stopped, the app's flows still pass, and variants were blocked.
- Almost everything for Node beyond detection rests on **one app, one live session**.
- Python repair is a **proof of concept on one bug**. It has no policy gate, no variant hardening, and is not yet wired into the main `fix` command.
- **IDOR and CSRF** can be detected in Node but have no probe in the code, so they cannot reach `proven` through the engine. (STATUS.md hints at oracles in the runner. The probe table in the code still lists them as unsupported.)
- **SQL/NoSQL, ReDoS, deserialization** have limited or no proof support.
- **open-redirect** was not fixed by any local model. Only a cloud model (`gpt-4.1-mini`) solved it.
- Two known detector gaps are marked `xfail` in tests: aliased destructured imports, and chained `router.route()`.
- A fuzzer or probe finding nothing means "not found", never "safe".
- Some roadmap numbers in `IMPROVEMENTS.md` are marked unverified by the author themselves.

---

## 10. Cheat sheet to explain it to anyone

> "It's an automatic security engineer. It **finds** a bug by reading code and following user input. It **proves** the bug by really attacking a safe local copy of the app. It asks an AI to **patch** just that function. Then plain code, not the AI, **checks the patch**: did it still start, did the attack stop, does the app still work, and do other forms of the attack also stop? If any check fails, the reason goes back to the AI to try again. We never trust the AI. We only trust tests. A weak AI just gets fewer fixes through, not wrong ones."

**Words to know:**

| Word | Meaning |
|---|---|
| Exploit / PoV | A replayable attack that proves a bug is real |
| Oracle | The rule that decides whether the attack worked (for example, response contains `21`) |
| Control request | The same request with harmless input, used to prove the oracle is not fooled |
| Variant | Another spelling of the same attack, used to catch overfitted patches |
| Gate | One pass/fail check a patch must clear |
| Regression | Checking the fix did not break normal features |
| Hardening | Trying to break our own patch before trusting it |
| Taint / flow analysis | Following user-controlled data to a dangerous call |
| Sink | A dangerous function (`eval`, a DB query, a redirect) |
| Sanitizer (ASan/UBSan) | Compiler tools that make memory bugs crash loudly (C only) |
| Fuzzing | Throwing huge amounts of random input at a program to cause crashes (C only) |
| Differential testing | Comparing patched and original behaviour on the same inputs |

---

## 11. Where to look in the code

| Topic | File |
|---|---|
| Node detection | `src/jsauto/static.py`, `flow.py`, `templates.py`, `deps.py` |
| Node exploit builder | `src/jsauto/probes.py`, `config/js_probes.json` |
| Node patch, policy, splice | `src/jsauto/patch.py` |
| Node repair loop and gates | `src/jsauto/repair.py` |
| Node full cycle | `src/jsauto/fix.py` |
| Python detection | `src/pyauto/static.py`, `config/semgrep/kavach_py.yaml` |
| Python dynamic probes | `src/pyauto/probes.py`, `probe_policy.py` |
| Python repair | `src/pyauto/repair.py`, `patch.py`, `runner.py` |
| HTTP attack engine (shared) | `benchmarks/oracles.py`, `benchmarks/nodegoat/exploit.py` |
| Test app harness (runner, flows, PoVs) | `benchmarks/nodegoat/` |
| C pipeline | `src/autonomy/`, `src/analysis_engine/`, `src/patch_validator/` |
| Sandbox, audit, pinning | `src/patch_validator/sandbox.py`, `src/agent_orchestrator/llm_client.py` |
