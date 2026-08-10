#!/bin/sh
# AI Kavach — Proof-of-Vulnerability runner (command-injection side effect).
#
# Usage: pov_injection.sh <binary>
#
# Feeds an argument containing a shell metacharacter payload that creates a
# marker file. If the marker appears, the injected command executed and the
# target is exploitable.
#
# Exit 0 => marker NOT created (injection blocked / vulnerability mitigated)
# Exit 1 => marker created (still exploitable)

marker="${TMPDIR:-/tmp}/ai_kavach_pov_$$_$(date +%s)"
rm -f "$marker"

"$1" "127.0.0.1; touch $marker" >/dev/null 2>&1

if [ -e "$marker" ]; then
    rm -f "$marker"
    exit 1
fi

exit 0
