#!/bin/sh
# Vanguard-04 proof-of-vulnerability: path traversal escape.
#
# Builds a sandbox that makes the escape observable:
#
#     <workdir>/secret.txt        <- OUTSIDE the storage root; must stay unreachable
#     <workdir>/rtos_storage/     <- the legitimate storage root
#                  config.txt     <- legitimate content (see regress_uri.sh)
#
# The URI "rtos://../secret.txt" becomes "rtos_storage/../secret.txt", which
# resolves back to <workdir>/secret.txt. The program prints "Opened: <path>"
# only when fopen() succeeded, so opening it proves the traversal worked.
#
# The earlier version of this check ran the binary against
# "/var/rtos/storage/../../../../etc/passwd" and inspected the exit code.
# parse_rtos_uri() returns 0 on every path, and /var/rtos/storage does not exist
# on a normal host, so that command exited 0 whether or not the program was
# vulnerable — it could never discriminate.
#
# Exit 0 => the file outside the root was NOT opened (vulnerability mitigated)
# Exit 1 => escape succeeded (still vulnerable)

set -e
BIN="$1"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/rtos_storage"
printf 'TOP_SECRET_CONTENT\n' > "$work/secret.txt"
printf 'legitimate=1\n' > "$work/rtos_storage/config.txt"

cd "$work"
output=$("$BIN" "rtos://../secret.txt" 2>&1 || true)

case "$output" in
    *"Opened:"*)
        echo "TRAVERSAL SUCCEEDED — read a file outside the storage root:"
        echo "$output"
        exit 1
        ;;
esac

exit 0
