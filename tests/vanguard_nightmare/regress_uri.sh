#!/bin/sh
# Vanguard-04 regression: legitimate storage access must keep working.
#
# The counterpart to pov_no_traversal.sh. A patch that simply refuses every URI
# would pass the PoV while destroying the feature, so this asserts that a normal
# file inside the storage root is still opened.
#
# Exit 0 => legitimate access preserved
# Exit 1 => the patch broke ordinary use

set -e
BIN="$1"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/rtos_storage"
printf 'legitimate=1\n' > "$work/rtos_storage/config.txt"

cd "$work"
output=$("$BIN" "rtos://config.txt" 2>&1 || true)

case "$output" in
    *"Opened:"*)
        exit 0
        ;;
esac

echo "REGRESSION: a legitimate file inside the storage root is no longer opened"
echo "$output"
exit 1
