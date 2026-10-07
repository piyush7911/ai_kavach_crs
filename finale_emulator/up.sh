#!/bin/sh
# Bring up the emulated finale VM with plain docker (no compose plugin needed).
#   ssh  -> localhost:2222  (root / kavach)
#   live -> http://localhost:4100
# Run from the repo root:  ./finale_emulator/up.sh
set -e
NET=kavach-emu-net
IMG=kavach-targetvm
SSH_PORT=${SSH_PORT:-2222}
APP_PORT=${APP_PORT:-4100}

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

echo "[up] mongo..."
docker rm -f kavach-emu-mongo >/dev/null 2>&1 || true
docker run -d --name kavach-emu-mongo --network "$NET" --network-alias mongo mongo:4.4 >/dev/null

echo "[up] building target image (needs internet the FIRST time only)..."
docker build -t "$IMG" -f finale_emulator/Dockerfile .

echo "[up] starting target VM..."
docker rm -f kavach-emu-targetvm >/dev/null 2>&1 || true
docker run -d --name kavach-emu-targetvm --network "$NET" \
  -p "${SSH_PORT}:22" -p "${APP_PORT}:4000" "$IMG" >/dev/null

echo "[up] waiting for the app to come healthy..."
for i in $(seq 1 60); do
  if curl -sf "http://localhost:${APP_PORT}/" >/dev/null 2>&1; then
    echo ""
    echo "  READY"
    echo "    ssh  : ssh root@localhost -p ${SSH_PORT}   (password: kavach)"
    echo "    live : http://localhost:${APP_PORT}"
    echo "    src  : /opt/app      tarball: /root/app.tar.gz      restart: /opt/restart.sh"
    exit 0
  fi
  sleep 2
done
echo "[up] app not healthy yet -> docker logs kavach-emu-targetvm"
exit 1
