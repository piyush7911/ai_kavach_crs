#!/bin/sh
# Boot the emulated VM: start sshd, then run the app in the foreground.
set -e
/usr/sbin/sshd
echo "[vm] sshd up on :22 (root / kavach)"
exec /opt/restart.sh --foreground
