#!/bin/sh
# Emulates the finale VM's restart.sh: (re)start the app from /opt/app so that
# any patch we scp into the source takes effect. Exit 0 = app healthy, non-zero = failed.
set -e
cd /opt/app

echo "[restart] stopping old app..."
pkill -f "node server.js" 2>/dev/null || true
sleep 1

echo "[restart] waiting for mongo..."
until nc -z mongo 27017 2>/dev/null; do sleep 1; done

echo "[restart] seeding db..."
node artifacts/db-reset.js || true

if [ "$1" = "--foreground" ]; then
  echo "[restart] starting app (foreground)..."
  exec node server.js
fi

echo "[restart] starting app (background)..."
nohup node server.js > /opt/app.log 2>&1 &

for i in $(seq 1 40); do
  if curl -sf http://127.0.0.1:4000/ >/dev/null 2>&1; then
    echo "[restart] healthy on :4000"
    exit 0
  fi
  sleep 1
done
echo "[restart] FAILED to come healthy"
tail -n 40 /opt/app.log || true
exit 1
