#!/bin/sh
# Makes a test certificate authority and a certificate for demo-shop.test. Run once.
set -e
cd "$(dirname "$0")"
mkdir -p pki && cd pki
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 365 \
  -subj "/CN=SecureCheck Lab CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=demo-shop.test" 2>/dev/null
printf "subjectAltName=DNS:demo-shop.test\nbasicConstraints=CA:FALSE\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365 -extfile ext.cnf 2>/dev/null
echo "Certificates written to lab/pki"
