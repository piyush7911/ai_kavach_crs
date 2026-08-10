#!/bin/sh
# AI Kavach — Proof-of-Vulnerability runner (sanitizer-based).
#
# Usage: pov_run.sh <binary> [args...]
#
# Exit 0  => the sanitized binary ran WITHOUT any memory-safety error.
#            (i.e. the vulnerability is NOT present / has been mitigated)
# Exit 1  => AddressSanitizer/UBSan fired, or the process died on a fatal
#            signal. The vulnerability still reproduces.
#
# This is the gate the DRV loop uses: a patch only passes if the exact input
# that crashed the original binary no longer triggers a sanitizer report.

ASAN_OPTIONS=detect_leaks=0
MallocNanoZone=0
export ASAN_OPTIONS MallocNanoZone

output=$("$@" 2>&1)
rc=$?

case "$output" in
    *"AddressSanitizer"*|*"UndefinedBehaviorSanitizer"*|*"runtime error:"*|*"LeakSanitizer"*)
        exit 1
        ;;
esac

# 128+N indicates death by signal N (SIGSEGV=139, SIGABRT=134, SIGBUS=138).
if [ "$rc" -ge 128 ]; then
    exit 1
fi

exit 0
