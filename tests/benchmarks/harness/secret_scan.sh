#!/bin/sh
# AI Kavach — hardening check for a hardcoded-secret fix (CWE-321/CWE-798).
#
# Usage: secret_scan.sh <binary> <forbidden-literal> <expected-stdout-substring> [args...]
#
# Why this exists
# ---------------
# Re-fuzzing cannot falsify this class of fix: a hardcoded key is not a crash,
# so there is no new crash to find. Differential testing cannot judge it either
# — the remediation IS to change the key, so the program's output is *supposed*
# to differ from the original. Holding it to behavioural equivalence rejects
# every correct patch.
#
# What can be falsified is the thing the fix claims: the secret is gone. A patch
# that renames the variable, moves the literal into a #define, or stores it in a
# different array still ships the secret in the binary, and `strings` finds it.
#
# Exit 0 => the literal is absent AND the program still works
# Exit 1 => the literal survives in the binary, or the patch broke the program
#
# The second condition is a vacuity guard: without it, a patch that deleted the
# whole function would "pass" by removing the string along with the feature.

BIN="$1"
FORBIDDEN="$2"
EXPECTED="$3"
shift 3

if [ ! -x "$BIN" ]; then
    echo "secret scan inconclusive: '$BIN' is not executable"
    exit 1
fi

# The literal must not survive anywhere in the compiled artefact.
if strings "$BIN" 2>/dev/null | grep -qF -- "$FORBIDDEN"; then
    echo "SECRET STILL PRESENT: the literal '$FORBIDDEN' is still embedded in the"
    echo "patched binary. Moving or renaming it does not remediate CWE-321 —"
    echo "the value has to stop being compiled in."
    exit 1
fi

# Vacuity guard: removing the secret by deleting the feature is not a fix.
output=$("$BIN" "$@" 2>&1)
rc=$?

if [ "$rc" -ne 0 ]; then
    echo "secret scan inconclusive: the patched program exited $rc, so 'secret"
    echo "absent' would be vacuous. Output: $output"
    exit 1
fi

case "$output" in
    *"$EXPECTED"*)
        exit 0
        ;;
esac

echo "secret scan inconclusive: expected stdout to still contain '$EXPECTED',"
echo "so the secret may be absent only because the feature was removed."
echo "actual output: $output"
exit 1
