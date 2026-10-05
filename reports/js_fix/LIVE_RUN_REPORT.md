# First live end-to-end run (Track 1 machine, 2026-10-06)

Setup: NodeGoat + MongoDB 4.4 + runner on this Mac; model `gemma4:e2b` over LAN
(192.168.0.103:11434 — note: STATUS said `gemma4:12b`, only `e2b` is loaded). 120 passed
/ 2 xfailed on the new unit tests. Runner start/replay/regress green on the untouched tree.

## open-redirect (JS-003) — unresolved (honest; gates worked)
confirmed: True, variants kept 4/4, 3 attempts, 4 model calls, 55s. Every attempt rejected
by a different gate — this is the system working:
- attempt 1 → **hardening**: primary blocked but variant 1/4 (`//kavach-probe.invalid/landing`,
  protocol-relative) still worked → overfitted, rejected.
- attempt 2 → **apply**: model output did not parse (gemma returned malformed JS).
- attempt 3 → **pov**: still exploitable.
Result `unresolved`. No fake fix was ever reported proven. e2b is too weak a repairer here;
expect 12b or a stronger model to pass.

## eval-injection (JS-002) — model produced a CORRECT fix, engine under-reported it
status `patched_unproven`, 2 model calls, 27s. The model rewrote
`eval(req.body.preTax)` → `Number(req.body.preTax)` (NaN on `6*4`) — a real fix.
**Track 1's confirmed PoV (`ng_eval_injection.json`, 6*4→24 oracle) says FIXED (bug gone).**
The engine reports it unproven only because its **own eval probe never confirmed the bug**
(`confirmed: False`), exactly the gap noted in STATUS §5: the 31338 oracle needs a page that
prints the result.

### Action for Track 2
Fix the eval-injection probe in `config/js_probes.json` so it confirms on NodeGoat. A working
oracle: POST /contributions with `preTax` an arithmetic expression (e.g. `6*4`) and check the
rendered contributions page contains the evaluated value (`>24 %<`) — i.e. eval computed it
where `Number`/`parseInt` would not. Then this finding would go `proven`.

## Net
Pipeline runs end to end: detect → confirm → model patch → policy/apply → PoV → regress →
hardening → final check, with every model call in the audit trace. Two gates demonstrably
caught bad patches; one real fix was produced and independently confirmed by Track 1.

## Update — first fully proven fix on the local model (2026-10-06)

After Track 2's probe fixes, re-ran eval-injection end to end with `gemma4:e2b` (LAN, no cloud):
**JS-002 → `proven (hardened)`**, 2 model calls, 36 s. confirmed=True, status=proven,
hardened=True, final check: 1 exploit blocked, 0 flows broken. The model's patch replaces
`eval(...)` with `Number(...)`. This is the full loop — detect → confirm → local-model patch →
policy → PoV → regression → hardening → proven — with no cloud and the weakest available model.
Open-redirect still needs a stronger model or a deterministic template (the apply/parse failures
dominate 8-attempt runs); yield, not safety, is the remaining lever.
