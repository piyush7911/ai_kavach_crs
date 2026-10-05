#!/usr/bin/env bash
# Clone OWASP NodeGoat at the pinned commit and install prod deps.
# Mongo is provided separately (docker run mongo:4.4 on 127.0.0.1:27017).
set -euo pipefail
DEST="${1:-benchmark_workspace/NodeGoat}"
COMMIT="c5cb68a"
if [ -d "$DEST/.git" ]; then echo "already present at $DEST"; exit 0; fi
git clone https://github.com/OWASP/NodeGoat.git "$DEST"
git -C "$DEST" checkout "$COMMIT"
( cd "$DEST" && npm install --omit=dev --no-audit --no-fund --ignore-scripts )
echo "NodeGoat ready at $DEST (commit $COMMIT)"
