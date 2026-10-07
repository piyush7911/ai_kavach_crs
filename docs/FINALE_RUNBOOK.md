# AI Kavach — Finale Runbook (offline reference)

> The one doc to follow during the live run. Every command is copy-pasteable.
> **Our laptop has no internet** at finale time — only a link to the VM. The local LLM runs on the
> same laptop. Everything here works offline **provided the pre-finale prep (§1) was done while online.**

---

## 0. Coordinates — fill these in first

Write the real values here at the start of the run, then every command below is copy-paste.

```
VM_USER=root                 # ssh user on the VM
VM_HOST=<VM_IP>              # ssh host of the VM
VM_PORT=22                   # ssh port
VM_PASS=<password>          # ssh password
LIVE=http://<LIVE_IP>:<PORT> # the running target app
SRC_PATH=/path/to/app        # the app's source path ON the VM (where restart.sh reads from)
TARBALL=/path/to/app.tar.gz  # the codebase tarball ON the VM
RESTART=/path/to/restart.sh  # restart script ON the VM
LLM=http://127.0.0.1:1234/v1 # local model on THIS laptop
MODEL=google/gemma-4-12b
KAVACH_REPO=/path/to/ai_kavach_crs   # where this repo is cloned on the laptop
```

Export them into the shell so the phase commands below just work:
```bash
export VM_USER VM_HOST VM_PORT VM_PASS LIVE SRC_PATH TARBALL RESTART KAVACH_REPO
export OPENAI_BASE_URL=$LLM MODEL_PROBE=$MODEL
```

> `scp`/`ssh` will prompt for `$VM_PASS`. To avoid repeated prompts install `sshpass` during prep (§1)
> and prefix commands with `sshpass -p "$VM_PASS"`.

---

## 1. Pre-finale prep — DO THIS WHILE ONLINE (dry-run with wifi OFF after)

Once we're at the venue there is no internet. Everything must already be on the laptop.

```bash
# 1.1 our tool + python deps
cd "$KAVACH_REPO"
pip install -r requirements.txt            # pulls everything now, cached offline

# 1.2 detection binaries (vendored/offline-capable)
#  - opengrep: ensure the binary is installed and the rule corpus is in the repo
opengrep --version                         # must print a version offline
#  - joern (optional): only needed for --joern-run; the run works without it

# 1.3 the LOCAL model (LLM must run on THIS laptop — the LAN box is unreachable offline)
#  - start LM Studio / llama.cpp serving an OpenAI-compatible endpoint on :1234
#  - confirm it answers with wifi OFF:
curl -s http://127.0.0.1:1234/v1/models | head

# 1.4 build the emulator image NOW (needs internet; §3 uses it offline later)
./finale_emulator/up.sh      # builds the image (first run) AND starts it

# 1.5 sshpass to avoid password prompts in scripted steps (optional but handy)
#     (brew install hudochenkov/sshpass/sshpass)  -- do while online

# 1.6 OFFLINE SMOKE TEST: turn wifi OFF, then run the full §3 emulator loop.
#     If it completes offline, we are finale-ready.
```

**Offline readiness checklist** (all must pass with wifi OFF):
- [ ] `curl http://127.0.0.1:1234/v1/models` returns the model
- [ ] `opengrep --version` works
- [ ] `python -m benchmarks.kavach --help` works
- [ ] emulator comes up and the §3 loop finds + proves + patches + restart-verifies

---

## 2. The finale environment (what they give us)

- A **VM**: SSH (user+password).
- A **live app**: `LIVE` (IP:port), reachable from our laptop.
- The **codebase**: a `tar.gz` and a source **path** on the VM.
- A **restart.sh** on the VM: re-launches the app from the source path (so a patch can be re-tested).

**Where things run:**
- **Laptop (no internet):** kavach (FIND/PROVE/FIX), the local LLM, report generation.
- **VM:** holds the source, runs the live app, runs `restart.sh`.
- **Gate for patches:** the VM. We patch the source, `restart.sh`, replay the exploit on `LIVE`.
  (We do **not** run the target app on the laptop — we can't install its deps offline.)

---

## 3. Rehearsal on the emulator (identical commands, local coordinates)

The emulator reproduces the finale VM on `localhost`. Use it to rehearse §4 end-to-end, offline.

```bash
# bring up the emulated VM (sshd on :2222, live app on :4100)
./finale_emulator/up.sh                      # prints READY + coordinates when healthy
docker logs -f kavach-emu-targetvm           # optional: watch the app boot
```

Emulator coordinates (plug into §0):
```
VM_USER=root  VM_HOST=localhost  VM_PORT=2222  VM_PASS=kavach
LIVE=http://localhost:4100
SRC_PATH=/opt/app   TARBALL=/root/app.tar.gz   RESTART=/opt/restart.sh
```

Smoke-check the pieces:
```bash
sshpass -p kavach ssh -o StrictHostKeyChecking=no -p 2222 root@localhost 'echo ssh-ok; ls /opt/app | head'
curl -s http://localhost:4100/ | head -c 120          # live app responds
```

Then run §4 with these coordinates. Tear down after:
```bash
./finale_emulator/down.sh
```

---

## 4. The run — phases (same for emulator and finale)

### Phase 0 — pull the source down to the laptop
```bash
cd "$KAVACH_REPO"
sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no -P "$VM_PORT" \
   "$VM_USER@$VM_HOST:$TARBALL" ./target.tar.gz
rm -rf target && mkdir target && tar xzf target.tar.gz -C target --strip-components=1
ls target            # sanity: source is here
```

### Phase 1 — route map (deterministic, from the local source)
```bash
python exp/scripts/route_map.py ./target > routes.json
wc -l routes.json
```

### Phase 2 — FIND + PROVE (static on local source, oracles over HTTP to LIVE)
```bash
python -m benchmarks.kavach \
  --target ./target --url "$LIVE" \
  --routes routes.json \
  --opengrep --live --misuse --idor \
  --out reports/report.json
```
Add `--auth auth.json` if we were given app credentials (see §6). Output:
- `reports/report.csv`  — the deliverable (confirmed vulns, 0-FP)
- `reports/report.json` — all findings incl. candidates
- `reports/coverage.json`, `reports/exchanges.jsonl`, `reports/llm_trace.jsonl`, `reports/run.json`

Quick look:
```bash
column -s, -t reports/report.csv | less -S
python -c "import json;d=json.load(open('reports/run.json'));print(d['confirmed'],'confirmed',d['candidates'],'candidate');print(d['confirmed_by_class'])"
```

### Phase 3 — FIX (patches generated on the laptop)
```bash
python -m benchmarks.kavach \
  --target ./target --url "$LIVE" \
  --routes routes.json \
  --opengrep --live --misuse --idor \
  --fix \
  --out reports/report.json
```
- **Template + config patches** are produced and self-verified offline (re-scan). No app restart needed.
- Patches land as unified diffs in `report.csv` / the `patch` field of `report.json`.
- The built-in **LLM (CEGIS) gate starts the app locally**, which we can't do offline — so LLM patches
  for code sinks are verified against the **VM** in Phase 4 instead.

Extract the diffs to apply:
```bash
python - <<'PY'
import json, os
d = json.load(open('reports/report.json'))
fs = d if isinstance(d, list) else d.get('findings', d)
os.makedirs('reports/patches', exist_ok=True)
for i, f in enumerate(fs):
    if f.get('patch'):
        open(f'reports/patches/{i:02d}_{f["klass"]}.diff','w').write(f['patch'])
        print('wrote', i, f['klass'], f.get('file'))
PY
ls reports/patches/
```

### Phase 4 — deploy each patch to the VM and verify via restart.sh
This is the correctness proof in the grading environment.
```bash
# for each diff in reports/patches/*.diff :
PATCH=reports/patches/00_weak-crypto.diff      # example

# 4a. push the patch up and apply it to the source on the VM
sshpass -p "$VM_PASS" scp -P "$VM_PORT" "$PATCH" "$VM_USER@$VM_HOST:/tmp/p.diff"
sshpass -p "$VM_PASS" ssh -p "$VM_PORT" "$VM_USER@$VM_HOST" \
   "cd $SRC_PATH && (git apply /tmp/p.diff || patch -p1 < /tmp/p.diff)"

# 4b. restart the app with the patched code
sshpass -p "$VM_PASS" ssh -p "$VM_PORT" "$VM_USER@$VM_HOST" "$RESTART"; echo "restart exit=$?"

# 4c. replay the exact confirming exploit against LIVE -> must NOT fire anymore
#     (the PoV + expected signal are in exchanges.jsonl / report.json for that finding)
python -m benchmarks.kavach --url "$LIVE" --routes routes.json \
   --replay reports/exchanges.jsonl --out reports/verify.json   # see note below
```

> **Replay note:** if a `--replay` flag isn't wired, verify manually — re-send the finding's PoV with
> `curl` using the request recorded in `exchanges.jsonl` and confirm the success marker is gone, then
> re-hit a couple of benign routes from `routes.json` and confirm identical responses (regression).
> Keep every before/after response as evidence.

### Phase 5 — collect deliverables
```bash
mkdir -p submission && cp reports/report.csv reports/report.json reports/coverage.json \
   reports/exchanges.jsonl reports/llm_trace.jsonl reports/run.json submission/
cp -r reports/patches submission/
ls -R submission
```
Submit: `report.csv` (the vuln report), the patch diffs, and the full audit bundle.

---

## 5. Command reference (flags)

| flag | meaning |
|---|---|
| `--target <dir>` | local source copy (static, opengrep, misuse, correlate, fix) |
| `--url <base>` | the live app (oracles, live checks, idor) |
| `--routes <json>` | route map from `exp/scripts/route_map.py` |
| `--auth <json>` | auth spec (roles/creds/login/CSRF) → authenticated confirmation |
| `--opengrep` | community taint corpus (cached by tree fingerprint) |
| `--live` | language-agnostic live HTTP oracles |
| `--misuse` | FP-safe source literals (weak hash/cipher/random, cookie flags) → confirmed |
| `--idor` | IDOR/BOLA candidates from the route map |
| `--fix` | template → config → CEGIS LLM patching |
| `--out <file.json>` | write JSON + CSV + coverage + exchanges + llm_trace + run.json |

Full example (authenticated):
```bash
python -m benchmarks.kavach --target ./target --url "$LIVE" --routes routes.json \
   --auth auth.json --opengrep --live --misuse --idor --fix --out reports/report.json
```

---

## 6. Auth spec (only if they give app credentials) — `auth.json`

```json
{
  "login_url": "/login",
  "method": "POST",
  "type": "form",
  "fields": {"username": "USER", "password": "PASS"},
  "csrf_field": "csrf_token",
  "roles": {
    "user":  {"username": "user1", "password": "pw1"},
    "admin": {"username": "admin", "password": "pw2"}
  }
}
```
Without `--auth`, authed classes (IDOR, authed injection) stay `candidate` — unauthenticated + config
findings still confirm. Reference specs: `config/nodegoat_auth.json`, `config/dvwa_auth.json`.

---

## 7. Troubleshooting (offline)

| symptom | fix |
|---|---|
| LLM calls fail | model server down → restart LM Studio/llama.cpp; `curl 127.0.0.1:1234/v1/models`. Note: FIND + template/config FIX work with the LLM off. |
| `--fix` says "LLM-fallback skipped" | expected offline if the target can't run locally; use the Phase-4 VM gate for code-sink patches. |
| opengrep: no rules | corpus not vendored → check repo; without it, first-party static still runs. |
| scp/ssh asks for password repeatedly | use `sshpass -p "$VM_PASS"`; add `-o StrictHostKeyChecking=no`. |
| `git apply` fails on the VM | fall back to `patch -p1 < p.diff`; check the diff's path prefix matches `$SRC_PATH`. |
| restart.sh exits non-zero | app didn't come healthy → `ssh ... 'tail -n 50 /opt/app.log'` (emulator) or the VM's log; revert the patch and re-test. |
| live app not reachable | confirm `curl "$LIVE"` from the laptop; check the IP/port and that the VM app is up. |
| route map empty | framework not auto-detected → pass routes manually or rely on `--live` + param-discovery over HTTP. |
| mongo/db errors (emulator) | `./finale_emulator/down.sh && ./finale_emulator/up.sh` to rebuild the pair. |

---

## 8. Golden path (TL;DR)

```bash
# prep (online, once): pip install -r requirements.txt ; build emulator ; start local model
# fill §0 coordinates, then:
sshpass -p "$VM_PASS" scp -P "$VM_PORT" "$VM_USER@$VM_HOST:$TARBALL" ./target.tar.gz
rm -rf target && mkdir target && tar xzf target.tar.gz -C target --strip-components=1
python exp/scripts/route_map.py ./target > routes.json
python -m benchmarks.kavach --target ./target --url "$LIVE" --routes routes.json \
   --opengrep --live --misuse --idor --fix --out reports/report.json
# apply each reports/patches/*.diff on the VM -> $RESTART -> replay PoV on $LIVE -> verify gone
# submit reports/report.csv + reports/patches/ + audit bundle
```
