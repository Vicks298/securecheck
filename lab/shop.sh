#!/bin/sh
# Starts or stops the Demo Shop (a web server and a DNS server) in the background.
#   sh lab/shop.sh weak     the shop before any fixes
#   sh lab/shop.sh fixed    the same shop after the fixes
#   sh lab/shop.sh stop
# Run it with the virtual environment active (source .venv/bin/activate).
cd "$(dirname "$0")"
PIDS=.shop.pids
stop() { if [ -f $PIDS ]; then kill $(cat $PIDS) 2>/dev/null; rm -f $PIDS; sleep 1; fi; }
case "$1" in
  stop) stop; echo "Demo Shop stopped." ;;
  weak|fixed)
    stop
    [ -f pki/ca.pem ] || sh make_certs.sh
    python3 lab.py "$1" >/dev/null 2>&1 & echo $! >> $PIDS
    python3 dns_server.py "$1" >/dev/null 2>&1 & echo $! >> $PIDS
    sleep 1
    echo "Demo Shop is running in the $1 state." ;;
  *) echo "usage: sh lab/shop.sh weak|fixed|stop"; exit 1 ;;
esac
