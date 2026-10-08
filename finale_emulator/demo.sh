#!/bin/sh
# One-command demo: pull source from the (emulated) VM, map routes, FIND + CONFIRM + FIX on NodeGoat,
# using the local Ollama model only. Run `./finale_emulator/up.sh` first to bring the VM up.
#
#   ./finale_emulator/up.sh      # start the target VM (once)
#   ./finale_emulator/demo.sh    # this script — the whole system, one command
#
# Self-contained: builds its own ssh/scp password helper (expect), no external tools needed beyond
# what macOS ships and this repo's own Python env. Entirely offline once the emulator image is built
# and Ollama is running locally — no internet used anywhere in this script.
set -e
cd "$(dirname "$0")/.."

VM_USER=user
VM_HOST=192.168.1.115
VM_PORT=80
VM_PASS=115@TCQ
LIVE=http://192.168.1.115
PY=/home/users/ai-kavach
[ -x "$PY" ] || PY=python3

echo "=== AI Kavach — offline demo run (Ollama) ==="
echo

echo "[0/5] checking Ollama is reachable..."
curl -sf -m 5 http://127.0.0.1:11434/api/tags >/dev/null || {
    echo "Ollama not reachable on 127.0.0.1:11434 — start it first (ollama serve)."; exit 1; }
curl -sf -m 5 "$LIVE/" -o /dev/null || {
    echo "$LIVE not reachable — is the emulator up? Run ./finale_emulator/up.sh first."; exit 1; }
echo "    ok."

SSHPASS_EXP="$(mktemp -t kavach_sshpass).exp"
cat > "$SSHPASS_EXP" <<'EOF'
#!/usr/bin/expect -f
set timeout 30
set pass [lindex $argv 0]
set cmd [lrange $argv 1 end]
log_user 0
eval spawn $cmd
expect {
    "*assword:*" { send "$pass\r"; exp_continue }
    "*yes/no*" { send "yes\r"; exp_continue }
    eof
}
catch wait result
exit [lindex $result 3]
EOF
chmod +x "$SSHPASS_EXP"
SSH="$SSHPASS_EXP $VM_PASS"

echo "[1/5] pulling source from the VM ($VM_HOST)..."
rm -f target.tar.gz
$SSH scp -o StrictHostKeyChecking=no -P "$VM_PORT" "$VM_USER@$VM_HOST:/home/user/ai-kavach/htc-wallet-offline-dev.tar.gz" ./target.tar.gz
rm -rf target && mkdir target && tar xzf target.tar.gz -C target --strip-components=1
echo "    $(find target -type f | wc -l | tr -d ' ') files pulled."

echo "[2/5] mapping routes (deterministic, no LLM)..."
$PY exp/scripts/route_map.py ./target routes.json

echo "[3/5] FIND + PROVE (static detection + live HTTP oracles + IDOR)..."
OPENAI_BASE_URL=http://127.0.0.1:11434/v1 MODEL_PROBE=codegemma:7b OPENAI_API_KEY=ollama \
$PY -m benchmarks.kavach \
    --target ./target --url "$LIVE" \
    --routes routes.json --auth config/nodegoat_auth.json \
    --opengrep --live --misuse --idor \
    --out reports/report.json

echo
echo "[4/5] FIX (deterministic template/config-fix first, local-model CEGIS fallback)..."
OPENAI_BASE_URL=http://127.0.0.1:11434/v1 MODEL_PROBE=codegemma:7b OPENAI_API_KEY=ollama \
$PY -m benchmarks.kavach \
    --target ./target --url "$LIVE" \
    --routes routes.json --auth config/nodegoat_auth.json \
    --opengrep --live --misuse --idor \
    --run-cmd 'MONGODB_URI=mongodb://127.0.0.1:27017/kavach_fixcheck PORT={port} node server.js' \
    --fix \
    --out reports/report.json

echo
echo "[5/5] summary"
$PY -c "
import json
d = json.load(open('reports/run.json'))
print(f\"    confirmed: {d['confirmed']}   candidates: {d['candidates']}\")
print(f\"    by class:  {d['confirmed_by_class']}\")
"
echo
echo "Deliverables in reports/: report.csv  report.json  coverage.json  run.json  exchanges.jsonl  llm_trace.jsonl"
echo "To deploy a fix and prove it live, see docs/FINALE_COMMANDS.md §6."
rm -f "$SSHPASS_EXP"
