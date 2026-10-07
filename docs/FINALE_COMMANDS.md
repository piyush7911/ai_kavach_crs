# Finale — command checklist (offline, no internet, self-contained)

Pure copy-paste commands only. For the why, see `FINALE_RUNBOOK.md`. Every command here was actually run
and verified against the local emulator (`finale_emulator/`) in a full rehearsal — including the bugs it
caught, listed in §7. If something on the day doesn't match what's below, trust what you observe over this
file and adapt; nobody can be reached to ask.

---

## 0. Fill in coordinates (do this first, at the venue)

```bash
export VM_USER=root
export VM_HOST=<VM_IP>
export VM_PORT=22
export VM_PASS=<password>
export LIVE=http://<LIVE_IP>:<PORT>
export KAVACH_REPO=/path/to/ai_kavach_crs
export LLM=http://127.0.0.1:1234/v1          # local model on THIS laptop (LM Studio) — or http://127.0.0.1:11434/v1 for Ollama
export MODEL="google/gemma-4-12b"             # or whatever is actually loaded — check with the command below
export OPENAI_BASE_URL=$LLM MODEL_PROBE=$MODEL OPENAI_API_KEY=x
cd "$KAVACH_REPO"
```

No `sshpass` on this laptop → every `ssh`/`scp` below will interactively prompt for `$VM_PASS`. That's fine,
just type it each time. (If `sshpass` happens to be installed, prefix commands with `sshpass -p "$VM_PASS"`
and add `-o StrictHostKeyChecking=no` to skip the prompt.)

## 1. Pre-flight checks (must all pass, wifi OFF)

```bash
curl -s "$LLM/models"                                      # local model answers
python -m benchmarks.kavach --help                          # our tool works
opengrep --version || echo "opengrep missing — static-only path still works without it"
ssh -p "$VM_PORT" "$VM_USER@$VM_HOST" 'echo ssh-ok'          # VM reachable (will prompt for password)
curl -sI "$LIVE"                                            # live app reachable
```

## 2. Pull the source down

```bash
scp -P "$VM_PORT" "$VM_USER@$VM_HOST:<TARBALL_PATH>" ./target.tar.gz
rm -rf target && mkdir target && tar xzf target.tar.gz -C target --strip-components=1
ls target          # sanity check
```

## 3. Route map (DETERMINISTIC, two positional args — NOT a stdout redirect)

```bash
python exp/scripts/route_map.py ./target routes.json
wc -l routes.json
```

## 4. FIND + PROVE

```bash
python -m benchmarks.kavach \
  --target ./target --url "$LIVE" \
  --routes routes.json \
  --opengrep --live --misuse --idor \
  --out reports/report.json
```

Add `--auth auth.json` (§8) if given app credentials — unlocks authenticated IDOR/BOLA and auth-gated routes.
Add `--llm-surface --llm-attacks` only if you have time to spare — on a local model this can take 5–10
minutes and may add zero extra confirmed findings (measured: 63 hypotheses → 0 confirmed in one run). Try
the plain command above first; add the LLM flags as a second pass if time allows.

**Read the result before moving on:**
```bash
column -s, -t reports/report.csv | less -S
python -c "import json;d=json.load(open('reports/run.json'));print(d['confirmed'],'confirmed',d['candidates'],'candidate');print(d['confirmed_by_class'])"
```

## 5. FIX (deterministic template/config-fix first, LLM only as fallback)

```bash
python -m benchmarks.kavach \
  --target ./target --url "$LIVE" \
  --routes routes.json \
  --opengrep --live --misuse --idor \
  --fix \
  --out reports/report.json
```

Config-fix remediations are **advisory snippets**, not auto-applied diffs — you still have to write them into
the source yourself (§6). LLM-CEGIS patches (when they appear) land as real unified diffs in the `patch`
field of `report.json` / `report.csv`.

```bash
python - <<'PY'
import json, os
d = json.load(open('reports/report.json'))
fs = d if isinstance(d, list) else d.get('findings', d)
os.makedirs('reports/patches', exist_ok=True)
for i, f in enumerate(fs):
    if f.get('patch'):
        open(f'reports/patches/{i:02d}_{f["klass"]}.diff', 'w').write(f['patch'])
        print('wrote', i, f['klass'], f.get('file'))
PY
```

## 6. Write and deploy each fix

**For every confirmed finding, whether it's an LLM diff or a manual config-fix snippet:**

1. Edit the fix into your **local** `./target/...` file (apply the diff by hand, or write the config-fix
   snippet in by hand — the snippet text and insertion point are in `patch_note` / `reports/report.csv`).
2. **Syntax-check locally before touching the VM** (this caught a real bug in rehearsal — do not skip):
   ```bash
   node --check target/path/to/file.js       # JS
   python -c "import ast; ast.parse(open('target/path/to/file.py').read())"   # Python
   javac -d /tmp/x target/path/to/File.java  # Java (needs javac + classpath; skip if unavailable, rely on step 4 below instead)
   ```
3. **Copy the whole changed file straight to the VM — do NOT rely on `git apply` / `patch -p1` on the VM.**
   The VM may not have `git` or `patch` installed (confirmed missing on the emulator). Copying the file
   directly needs neither and is the robust path:
   ```bash
   scp -P "$VM_PORT" target/path/to/file.ext "$VM_USER@$VM_HOST:<SRC_PATH>/path/to/file.ext"
   ```
4. **Restart:**
   ```bash
   ssh -p "$VM_PORT" "$VM_USER@$VM_HOST" "<RESTART_PATH>"; echo "restart exit=$?"
   ```
   A non-zero exit or a health-check failure means the app crashed — check the VM's app log over SSH, revert
   the file (re-copy the pre-patch version), restart again, and only then investigate.
5. **Re-verify for real — do not trust the patch, trust a fresh run:**
   ```bash
   curl -sI "$LIVE/<the route that was vulnerable>"     # eyeball the specific fact (header/cookie/etc.)
   python -m benchmarks.kavach --url "$LIVE" --routes routes.json --live --idor --out reports/verify.json
   ```
   The confirmed finding for that class must be **gone** from `reports/verify.json`/`.csv`, and nothing new
   should appear. If the app now 500s on requests that used to work, the fix is broken — revert it (go back
   to step 4 with the original file) rather than ship a patch that breaks the app.

## 7. Known traps (all hit for real in rehearsal — check for these specifically)

| Symptom | Cause | Fix |
|---|---|---|
| Route map crashes with an `IndexError` | ran `route_map.py` with only one arg / `>` redirect | use the two-arg form in §3 exactly |
| `git apply`/`patch` says "not found" on the VM | neither tool installed | copy the whole file instead (§6 step 3) |
| A patch you deployed doesn't seem to take effect at all | the app may be running as PID 1 and your restart script's `pkill` can't kill it (containers silently ignore SIGTERM to PID 1 with no handler) | check `ps aux` on the VM — if the app is PID 1, this restart mechanism can't actually replace it; flag it, don't assume the patch failed |
| App works when you `ssh` in manually but breaks / misconfigures after `restart.sh` | an SSH login shell does NOT inherit the process that originally launched the app's environment variables (confirmed: `/proc/1/environ` had them, an SSH shell's own `$VAR` did not) | check `restart.sh` exports any required env vars itself; if it doesn't and you can't edit it, export them manually before invoking it over SSH |
| A config-fix snippet you applied crashes every request with an obscure internal-library stack trace | the exact library version on this target may be incompatible with the generic snippet (hit this with `csurf@1.9.0` + old `express`) | this is exactly what step 6.5 (re-verify) is for — if it breaks, revert immediately, don't debug library internals under time pressure |
| `node --check`/syntax-check passes but the app still crashes at runtime with `ReferenceError` | a snippet referenced a variable (e.g. `helmet`) whose `require()` was itself commented out elsewhere in the file | prefer self-contained snippets with an inline `require(...)` over ones assuming a top-level import exists |
| `--fix`'s LLM-fallback says "skipped" | no `--url` + `OPENAI_BASE_URL`, or (py/js) no `--run-cmd` | expected if offline/local-run isn't possible — deterministic template/config fixes still work without it; use the VM-restart loop (§6) to verify LLM patches instead |

## 8. Auth spec (only if given app credentials) — `auth.json`

```json
{
  "login_path": "/login",
  "user_field": "userName",
  "pass_field": "password",
  "roles": {
    "user":  ["user1", "pw1"],
    "admin": ["admin", "pw2"]
  }
}
```
Field names/path must match the real app's login form — check the HTML (`curl -s "$LIVE/login"`) if unsure.
Without `--auth`, authed classes (IDOR, authed injection) stay `candidate` — unauthenticated + config/live
findings still confirm fine.

## 9. Collect deliverables

```bash
mkdir -p submission
cp reports/report.csv reports/report.json reports/coverage.json \
   reports/exchanges.jsonl reports/llm_trace.jsonl reports/run.json submission/ 2>/dev/null
cp -r reports/patches submission/ 2>/dev/null
ls -R submission
```
Submit `report.csv` (the vuln report), the patch diffs, and the full audit bundle (`run.json` indexes
everything, including which were actually VM-verified vs advisory-only).

---

## Golden path (if everything goes right, start to finish)

```bash
# §0 — fill in and export coordinates
scp -P "$VM_PORT" "$VM_USER@$VM_HOST:<TARBALL_PATH>" ./target.tar.gz
rm -rf target && mkdir target && tar xzf target.tar.gz -C target --strip-components=1
python exp/scripts/route_map.py ./target routes.json
python -m benchmarks.kavach --target ./target --url "$LIVE" --routes routes.json \
   --opengrep --live --misuse --idor --fix --out reports/report.json
# for each confirmed finding: edit target/..., syntax-check, scp the whole file, restart, re-verify (§6)
mkdir -p submission && cp reports/report.csv reports/report.json reports/*.jsonl reports/run.json submission/
```
