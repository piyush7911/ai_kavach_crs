# What we found, confirmed, and fixed — and why it carries to any app

Plain-language reference. Two practice apps: **VAmPI** (Python/Flask API) and **NodeGoat** (Node.js web
app). For each bug: did we *find* it, *confirm* it, *fix* it, how — and whether the same machinery works
on a different app we've never seen.

---

## 30-second primer (the words we use)

- **Vulnerability (vuln)** — a weakness an attacker can abuse (e.g. read someone else's data).
- **Find / detect** — notice a bug might exist. Two ways: **static** (read the source code) and
  **dynamic / probe** (poke the running app over the network and watch how it answers).
- **Confirm** — *prove* the bug is real by actually exploiting it against the live app. Our rule:
  nothing counts as a bug until a real request demonstrates it. A guess is not a finding.
- **Oracle** — the little judge that decides "did the attack work?". Each bug class has one.
- **PoV (Proof of Vulnerability)** — the exact request(s) that trigger the bug. Replayable = we can
  fire it again any time (e.g. to check a fix worked).
- **Fix / patch** — rewrite the vulnerable function so the bug is gone.
- **Gate** — the automatic check that only accepts a patch if: the PoV no longer works **and** normal
  use still works (**regression**) **and** sneaky variants of the attack are also blocked (**hardening**).
- **The two clever oracle tricks** (they need no app-specific knowledge, which is why they travel):
  - **Differential** — send one request that should be "always true" and one "always false". If the app
    answers them *differently*, our input reached somewhere it shouldn't (used for injection).
  - **Metamorphic** — do the *same* action as an allowed user and as a not-allowed user. If both are
    served, the access check is broken (used for authorization bugs).

---

## VAmPI (Python/Flask) — its own list is 9, plus 2 bonuses we caught

| # | Vulnerability (meaning) | Found? how | Confirmed? how | Fixed? how |
|---|---|---|---|---|
| 1 | **SQL injection** — attacker text becomes part of a database query | ✅ probe (differential) | ✅ true-vs-false query answers differ | ✅ **proven** — model rewrote it to a *parameterized query* (input treated as data, never code) |
| 2 | **BOLA, password** — change *another* user's password (Broken Object-Level Authorization = no ownership check) | ✅ probe (metamorphic) | ✅ a non-owner's request is served | ✅ **proven** — added an ownership check |
| 3 | **BOLA, books** — read another user's private book | ✅ probe (setup + metamorphic) | ✅ create a book as A, read it as B | ✅ **proven** — ownership check |
| 4 | **Mass assignment** — sign up but also secretly set `admin=true` | ✅ probe (register + escalation test) | ✅ the self-made "admin" did an admin-only action | ⚠️ **not auto-fixed yet** — its proof isn't a single replayable request the gate can replay (bespoke check); known gap |
| 5 | **Excessive data exposure** — a debug page dumps everyone's passwords | ✅ probe (secret word in the reply) | ✅ passwords visible in the response | ✅ **proven** (dedicated driver) — stop returning secret fields |
| 6 | **User enumeration** — login tells you which usernames exist | ✅ probe (differential on login) | ✅ "wrong user" vs "wrong password" answers differ | ✅ **proven** — identical error for both |
| 7 | **ReDoS** — a crafted string makes a regex hang (denial of service) | ⛔ not live-probed | ⛔ inspection only | — **by rule**: a live proof *is* a DoS, which the competition forbids |
| 8 | **No rate limiting** — hammer an endpoint, never get blocked | ⛔ not blind-probed | ✅ when pointed (no 429 under load) | — fix is *middleware* (app-wide), not a one-function rewrite |
| 9 | **Weak JWT key** — login tokens signed with a guessable secret | ✅ static (hard-coded secret in code) | ✅ a token signed with the weak key is accepted | — fix is "read key from environment"; has no single live PoV to prove-after |
| + | **BOLA, email** (bonus) — change another user's email | ✅ probe (metamorphic) | ✅ non-owner served | ✅ **proven** — ownership check |
| + | **Flask debug=True** (bonus misconfig) | ✅ static | n/a | — config change |

**VAmPI fix score: 5 of 6 attempted bugs proven** (SQLi, both BOLAs, books-BOLA, enumeration; only the
debug-dump missed in the combined run). Every non-fix was *rejected by the gate* — no broken patch shipped.

---

## NodeGoat (Node.js) — 7 runtime bugs + 4 static-only + 1 forbidden

| Vulnerability (meaning) | Found? how | Confirmed? how | Fixed? how |
|---|---|---|---|
| **NoSQL injection** — like SQLi but for a MongoDB query | ✅ probe (differential) | ✅ true-vs-false differ | ✅ **proven** |
| **eval injection** — attacker input gets run as code (`eval`) | ✅ probe | ✅ `6*4` came back as `24` | ✅ **proven + hardened** |
| **Stored XSS** — attacker script saved, runs in a victim's browser | ✅ probe | ✅ our script tag survived in the page | ❌ model couldn't fix in the tries (gate rejected its attempts) |
| **SSRF** — make the server fetch a URL of the attacker's choice (Server-Side Request Forgery) | ✅ probe (callback server) | ✅ our server received the call-back | ✅ **proven + hardened** |
| **Open redirect** — a link on the site bounces you to an attacker site | ✅ probe | ✅ redirect went to our domain | ✅ **proven + hardened** |
| **IDOR, read** (allocations) — view another user's data by changing an id in the URL | ✅ probe (two-id read-diff) | ✅ a different id returns different data | ✅ **proven** — ownership check |
| **IDOR, write** (benefits) — a normal user edits another user's record | ✅ probe (verify-after-write) | ✅ wrote a marker into a victim's record, saw it on read-back | ⚠️ likely *middleware* fix (add admin-only to the route), not the handler — repair-TBD |
| hardcoded secret / private key / insecure cookie / missing CSRF | ✅ static | — (no runtime PoV) | — static-only, reported |
| **ReDoS** | ⛔ forbidden (DoS) | — | — |

**NodeGoat fix score: 5 of 6 confirmed-and-gated bugs proven, 3 hardened** (nosql, eval, open-redirect,
ssrf, read-IDOR; only XSS missed). "Hardened" = we also tried other spellings of the attack and the patch
blocked them too, so it's a real fix, not a block of one exact string.

---

## "Will this work on a DIFFERENT app?" — yes, and here is exactly why

The whole design separates **what's app-specific** from **what's universal**:

- **App-specific = tiny and swappable.** Only two things differ per app: *how to log in* (a small config:
  VAmPI uses a JWT token, NodeGoat uses a cookie) and *where the routes are* (we read them from the app's
  own route list / OpenAPI, or from the live server — never hard-coded). That's it.
- **Universal = everything that does the real work.** The oracles speak plain **HTTP**, not Python or
  JavaScript. They don't know or care what language the app is in. **We proved this literally**: the
  oracles were written for NodeGoat (JS), and ran *unchanged* to confirm VAmPI (Python) bugs — only the
  login config changed.

How each oracle carries to a brand-new app, in one line:

| Bug class | Why it generalizes (the trick needs no app knowledge) |
|---|---|
| SQL / NoSQL injection | **Differential**: "always-true vs always-false". If any input field changes the answer, input reached the query — true for *any* app, any database. |
| BOLA / IDOR (read) | **Metamorphic** / two-id: ask for someone else's object; if you get different data, there's no ownership check. No app-specific marker needed. |
| IDOR / authz (write) | **Verify-after-write**: write a unique marker into another user's record, read it back; if it's there, you edited data you don't own. Works wherever a write has a matching read. |
| Access control / privilege | **Metamorphic roles**: do the same action as an allowed and a not-allowed user; if both succeed, the check is missing. |
| Data exposure | Look for secret-looking fields (password/token/secret) in any response. Field names are universal. |
| User enumeration | **Differential on login**: does "unknown user" answer differently from "wrong password"? |
| SSRF | Tell the app to fetch *our* one-time server; if our server gets pinged, it fetched attacker input. Language-independent. |
| XSS / open-redirect / eval | Send a marker payload, check the response reflects/executes/redirects it. The marker is ours, not the app's. |

**Finding bugs on an unknown app:** we don't need its documentation. We read its live routes (every web
framework exposes them), guess the missing bits by probing (is this route login-protected? what fields
does it take?), then run every oracle against every route. We showed this **spec-free** mode find the
same bugs on VAmPI with the manual (OpenAPI) spec removed.

**Fixing bugs on an unknown app:** the model rewrites one function; the **gate** decides using the app's
own behavior (replay the PoV, check normal use still works). The gate is the safety net — if the model's
fix is wrong, it's rejected, never shipped. That logic is identical regardless of app or language.

## The honest limits (so nothing is oversold)

- **Forbidden by the rules:** ReDoS and rate-limiting aren't live-probed (a proof would be a
  denial-of-service attack, which the competition bans). We flag them by inspection.
- **Middleware / config fixes** (rate-limiting, missing admin-check on a route, read-secret-from-env):
  our repair rewrites a *function*; these fixes live in route setup or config, so they're detect-and-
  report, not auto-patch-yet.
- **Model capability:** two bugs (NodeGoat XSS, VAmPI debug-dump) weren't fixed by the current model —
  but the gate *rejected* the bad attempts, so nothing unsafe shipped. A stronger model closes these.
