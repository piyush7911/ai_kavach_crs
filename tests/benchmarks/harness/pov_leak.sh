#!/bin/sh
# AI Kavach — Proof-of-Vulnerability runner for memory leaks (CWE-401).
#
# Usage: pov_leak.sh <binary> [args...]
#
# Exit 0 => LeakSanitizer found nothing (the leak has been fixed)
# Exit 1 => a leak was reported, or the run died
#
# Why this is separate from pov_run.sh
# -----------------------------------
# Every other runner exports ASAN_OPTIONS=detect_leaks=0. That is deliberate:
# leak checking at process exit turns unrelated one-off allocations in a target's
# own main() into failures, which would make the memory-safety gates noisy.
#
# The consequence was that leaks became untestable, and this project recorded the
# reason as "LeakSanitizer is not supported on darwin-arm64". That is false —
# measured here, LSan runs on arm64 macOS and exits 1 on a leak and 0 without
# one. It was only ever switched off. This runner switches it back on for the
# targets whose weakness IS the leak.
#
# `exitcode=1` is set explicitly so a leak is a failure rather than a printed
# warning, matching -fno-sanitize-recover=all for the other sanitizers.

ASAN_OPTIONS=detect_leaks=1:exitcode=1
MallocNanoZone=0
export ASAN_OPTIONS MallocNanoZone

output=$("$@" 2>&1)
rc=$?

case "$output" in
    *"LeakSanitizer: detected memory leaks"*)
        echo "$output"
        exit 1
        ;;
    *"AddressSanitizer"*|*"UndefinedBehaviorSanitizer"*|*"runtime error:"*)
        echo "$output"
        exit 1
        ;;
esac

if [ "$rc" -ne 0 ]; then
    echo "process exited $rc; output follows:"
    echo "$output"
    exit 1
fi

exit 0
