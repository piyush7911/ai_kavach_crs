#!/bin/sh
# Tear down the emulated finale VM.  Run from repo root:  ./finale_emulator/down.sh
docker rm -f kavach-emu-targetvm kavach-emu-mongo >/dev/null 2>&1 || true
docker network rm kavach-emu-net >/dev/null 2>&1 || true
echo "emulator down"
