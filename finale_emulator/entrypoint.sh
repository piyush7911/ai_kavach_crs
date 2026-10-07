#!/bin/sh
# Boot the emulated VM: start sshd, then run the app in the BACKGROUND (never as PID 1).
#
# Found by actually running the rehearsal: the app must never be PID 1. A later `restart.sh` (always
# invoked over SSH, like the real finale flow) does `pkill -f "node server.js"` to replace it — but
# SIGTERM against PID 1 with no handler installed is silently ignored by the kernel (the classic
# "my container's init process won't die" trap), so the ORIGINAL unpatched process kept serving
# forever and a patch looked like it had no effect. PID 1 here is a trivial wait loop instead, so the
# app itself is always an ordinary, killable child process from the very first boot.
set -e
/usr/sbin/sshd
echo "[vm] sshd up on :22 (root / kavach)"
/opt/restart.sh
echo "[vm] app started (background, PID 1 stays free for restart.sh to replace it later)"
exec tail -f /dev/null
