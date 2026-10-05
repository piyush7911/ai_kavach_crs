#!/bin/sh
# Vanguard-04 evasion battery — hardening for an input-validation fix.
#
# Adversarial re-fuzzing falsifies a memory-safety patch by finding another
# crash. A path-traversal fix has no crash to find: it fails by letting a
# cleverer payload through. This tries a spread of bypass encodings against the
# PATCHED build and fails if any of them still escapes the storage root.
#
# The variants target the ways a naive sanitiser breaks:
#   ../secret.txt          the plain case (same as the PoV)
#   ....//secret.txt       survives a single non-recursive strip of ".."
#   sub/../../secret.txt   escape via a legitimate-looking subdirectory
#   ./../secret.txt        leading "./" before the traversal
#   .././secret.txt        interleaved separators
#   ..//secret.txt         doubled separator after ".."
#
# Exit 0 => no variant escaped (patch holds)
# Exit 1 => at least one escaped (patch falsified)

BIN="$1"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/rtos_storage/sub"
printf 'TOP_SECRET_CONTENT\n' > "$work/secret.txt"
printf 'legitimate=1\n' > "$work/rtos_storage/config.txt"

cd "$work" || exit 1

escaped=""
for payload in \
    "rtos://../secret.txt" \
    "rtos://....//secret.txt" \
    "rtos://sub/../../secret.txt" \
    "rtos://./../secret.txt" \
    "rtos://.././secret.txt" \
    "rtos://..//secret.txt"
do
    out=$("$BIN" "$payload" 2>&1 || true)
    case "$out" in
        *"Opened:"*)
            escaped="$escaped
  BYPASS: $payload -> $out"
            ;;
    esac
done

if [ -n "$escaped" ]; then
    echo "evasion battery found a bypass of the traversal check:$escaped"
    exit 1
fi

# Sanity: the battery must not pass merely because the program refuses
# everything. A legitimate read has to still work, or a patch that rejects all
# input would score as hardened.
legit=$("$BIN" "rtos://config.txt" 2>&1 || true)
case "$legit" in
    *"Opened:"*) exit 0 ;;
esac

echo "evasion battery inconclusive: legitimate access is broken, so 'no bypass'"
echo "would be vacuous. Output: $legit"
exit 1
