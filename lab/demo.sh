#!/bin/sh
# Runs the whole demo: scan the fake shop before fixes, apply the fixes, scan again, compare.
# Needs: sh lab/make_certs.sh (once) and "127.0.0.1 demo-shop.test" in /etc/hosts.
cd "$(dirname "$0")/.."
if ! getent hosts demo-shop.test >/dev/null; then
  echo 'First run:  echo "127.0.0.1 demo-shop.test" | sudo tee -a /etc/hosts'; exit 1
fi
[ -f lab/pki/ca.pem ] || sh lab/make_certs.sh
RUN="python3 run.py demo-shop.test --by ${1:-Demo} --only email,tls,headers,paths --dns 127.0.0.1:5353 --https-port 8443 --http-port 8080 --ca-file lab/pki/ca.pem"
stop() { kill $L $D 2>/dev/null; wait $L $D 2>/dev/null; }
trap stop EXIT
for step in weak fixed; do
  python3 lab/lab.py $step >/dev/null 2>&1 & L=$!
  python3 lab/dns_server.py $step >/dev/null 2>&1 & D=$!
  sleep 1
  name=$([ $step = weak ] && echo before || echo after)
  echo "=== $name (shop is $step) ==="
  $RUN --json $name.json --pdf $name.pdf | grep -E "^\[|Saved"
  stop
done
echo; echo "=== COMPARE ==="
python3 compare.py before.json after.json
