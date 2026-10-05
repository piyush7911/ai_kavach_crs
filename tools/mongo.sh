#!/bin/sh
# Local MongoDB 4.4 for the NodeGoat benchmark (NodeGoat's driver cannot talk to MongoDB 5.1+).
# Loopback only. The binary is x86_64 and runs under Rosetta 2 on Apple silicon.
#   sh tools/mongo.sh start | stop | status
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/mongodb-4.4.29/bin/mongod"
DATA="$HERE/mongo-data"
case "$1" in
  start)
    mkdir -p "$DATA"
    if nc -z -w1 127.0.0.1 27017 2>/dev/null; then echo "already listening on 127.0.0.1:27017"; exit 0; fi
    "$BIN" --dbpath "$DATA" --bind_ip 127.0.0.1 --port 27017 --nounixsocket --fork --logpath "$DATA/mongod.log" >/dev/null \
      || { echo "mongod failed to start; see $DATA/mongod.log"; exit 1; }
    for i in 1 2 3 4 5 6 7 8 9 10; do nc -z -w1 127.0.0.1 27017 2>/dev/null && { echo "mongod up on 127.0.0.1:27017"; exit 0; }; sleep 1; done
    echo "mongod did not come up in 10 s; see $DATA/mongod.log"; exit 1 ;;
  stop)
    "$BIN" --dbpath "$DATA" --shutdown ;;
  status)
    nc -z -w1 127.0.0.1 27017 2>/dev/null && echo "up (127.0.0.1:27017)" || { echo "down"; exit 1; } ;;
  *) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
