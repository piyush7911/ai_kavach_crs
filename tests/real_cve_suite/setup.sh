#!/bin/sh
# Materialise the vulnerable source trees for the real-CVE suite.
#
# Nothing here is vendored: each tree is upstream cJSON checked out at the exact
# commit BEFORE the security fix landed. Re-runnable and idempotent.
#
#   sh tests/real_cve_suite/setup.sh
#
# Trees are created under benchmark_workspace/ (gitignored). Delete that
# directory and re-run to rebuild from scratch.

set -e

REPO_URL="https://github.com/DaveGamble/cJSON.git"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CLONE="$ROOT/benchmark_workspace/cJSON_cve"
TREES="$ROOT/benchmark_workspace/real_cve_trees"

# Vulnerable commit for each CVE = the parent of the upstream fix.
#   CVE-2019-11835  cJSON_Minify OOB read      fixed by the 1.7.11 rewrite
#   CVE-2019-11834  parse_string over-read     fixed by a167d9e
#   GH-800          parse_object trailing comma OOB   fixed by 3ef4e4e
VULN_MINIFY="v1.7.10"
VULN_PARSE_STRING="b537ca70a35680db66f1f5b8b437f7114daa699a"
VULN_PARSE_OBJECT="826cd6f842ae7e46ee38bbc097f9a34f2947388d"

if [ ! -d "$CLONE/.git" ]; then
    echo "cloning cJSON -> $CLONE"
    git clone -q "$REPO_URL" "$CLONE"
fi

mkdir -p "$TREES"

add_tree() {
    name="$1"; commit="$2"
    path="$TREES/$name"
    if [ -f "$path/cJSON.c" ]; then
        echo "  $name: already present"
        return
    fi
    rm -rf "$path"
    git -C "$CLONE" worktree prune
    git -C "$CLONE" worktree add -q --detach "$path" "$commit"
    echo "  $name: $(git -C "$path" log -1 --format=%h)"
}

echo "materialising vulnerable trees:"
add_tree cjson_minify_oob       "$VULN_MINIFY"
add_tree cjson_parse_string_oob "$VULN_PARSE_STRING"
add_tree cjson_parse_object_oob "$VULN_PARSE_OBJECT"

echo
echo "done. run the suite with:"
echo "  python -m tests.real_cve_suite.run_real_cve"
echo "  python benchmark.py --suite real_cve --harden"
