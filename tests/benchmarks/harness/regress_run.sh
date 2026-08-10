#!/bin/sh
# AI Kavach — Regression runner.
#
# Usage: regress_run.sh <binary> <expected-stdout-substring> [args...]
#
# Runs the patched binary on a BENIGN input and asserts that:
#   1. it exits 0,
#   2. no sanitizer fired,
#   3. stdout still contains the expected substring (behaviour preserved).
#
# Pass "-" as the expected substring to only check exit status / sanitizers.
#
# Exit 0 => no regression. Exit 1 => the patch broke valid behaviour.

ASAN_OPTIONS=detect_leaks=0
MallocNanoZone=0
export ASAN_OPTIONS MallocNanoZone

bin="$1"
expected="$2"
shift 2

output=$("$bin" "$@" 2>&1)
rc=$?

if [ "$rc" -ne 0 ]; then
    echo "REGRESSION: benign input exited with status $rc"
    echo "$output"
    exit 1
fi

case "$output" in
    *"AddressSanitizer"*|*"UndefinedBehaviorSanitizer"*|*"runtime error:"*)
        echo "REGRESSION: sanitizer fired on benign input"
        echo "$output"
        exit 1
        ;;
esac

if [ "$expected" != "-" ]; then
    case "$output" in
        *"$expected"*) ;;
        *)
            echo "REGRESSION: expected stdout to contain '$expected'"
            echo "actual output: $output"
            exit 1
            ;;
    esac
fi

exit 0
