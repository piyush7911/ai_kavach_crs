# Repair performance by model — NodeGoat (JS) and VAmPI (Python)

How well the autonomous repair loop fixes the bugs we discover + confirm, with two local-class models.
Discovery and verification are model-independent (deterministic); this measures only **fix quality**:
a bug counts PROVEN only when the gate replays the exploit against the patched app and it is gone, the
regression/golden flows still pass, and (JS) the exploit's variants are also blocked (HARDENED).

- **codegemma:7b** — local (Ollama), the finalist local model. 7B.
- **nvidia.nemotron-nano-3-30b** — NVIDIA, 30B, via an OpenAI-compatible endpoint (AWS Bedrock here).
  Non-Chinese, so within the model rules. For the air-gapped finale it would run locally (30B weights).

## NodeGoat — `benchmarks.ngautofix` (6 confirmed-reproducing findings)

The driver now **confirms each exploit reproduces on the untouched app before repairing** — a
non-reproducing exploit would otherwise pass the "pov gone" gate trivially (a false proof). That is why
the denominator is the 6 confirmed, not the 7 with an exploit attached: the benefits write-IDOR builds an
exploit but does not reproduce via the read-diff oracle, so it is correctly dropped, not fixed.

| finding | nemotron-30b |
|---|---|
| nosql-injection (`searchCriteria`) | **proven** |
| idor — allocations (`displayAllocations`) | **proven** |
| eval-injection (`handleContributionsUpdate`) | **proven + hardened** |
| open-redirect (`index.js` handler) | **proven + hardened** |
| ssrf (`displayResearch`) | **proven + hardened** |
| xss (`handleProfileUpdate`) | unresolved† |
| **total** | **5 / 6 (3 hardened)** |

† nemotron returned the same patch twice; the loop stopped (at temperature 0 a repeat only repeats the
rejection). xss is nemotron's one consistent blind spot here.

## VAmPI — `benchmarks.pyautofix_vampi` (6 repairable findings)

| finding | codegemma:7b | nemotron-30b |
|---|---|---|
| SQL injection (`get_by_username`) | proven | **proven** |
| BOLA password change (`update_password`) | rejected | **proven**‡ |
| BOLA email change (`update_email`) | rejected | **proven** |
| books-BOLA (`get_by_title`) | proven | **proven** |
| excessive-data-exposure (`debug`) | rejected§ | rejected§ |
| user-enumeration (`login_user`) | proven | **proven** |
| **total** | **3 / 6** | **5 / 6** |

‡ password-BOLA first looked like a model miss but was a HARNESS bug: the exploit changes the owner's
own password, so the regression's "log back in as that owner" then failed for any patch. Fixed by
running the password regression as `admin` (a role the user-level PoV never touches); nemotron's fix
then proved. A good example of the gate being conservative — it rejected until the check itself was sound.
§ both models kept a sensitive field across 3 tries; the gate rejected every attempt — no bad fix
shipped. `/_debug` is fixed reliably by the dedicated single-bug driver (`pyrepair_vampi`).

## Takeaway

- **Verification holds the line regardless of model.** Every miss above is a *rejected* patch, not a
  false "fixed": the gate replayed the exploit (and, on JS, its variants) and refused anything that left
  the bug exploitable or broke a legitimate flow. The weak model is the limit, never safety.
- **nemotron-30b > codegemma:7b**: VAmPI 5/6 vs 3/6 (adds both email- and password-BOLA), and it fixes
  bugs with reasoning (SQLi parameterization, ownership/authorization checks, IDOR) rather than
  pattern-matching — including the newly-added allocations IDOR.
- **Combined, nemotron fixes 10 of 12 across both stacks** (VAmPI 5/6 + NodeGoat 5/6) end-to-end with
  proof, on apps the engine was never written for. The two misses are model capability (xss,
  data-exposure), not pipeline gaps — a stronger or ensembled model closes them, and the gates
  guarantee no regression if it does not.
