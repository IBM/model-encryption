#!/usr/bin/env bash

# create root-ca
openssl genrsa -out ca-priv.pem 4096

openssl req -new -x509 \
	-key ca-priv.pem \
	-out ca-cert.pem \
	-days 3650 \
	-subj "/CN=root-ca" \
	-extensions v3_ca \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign"

# create intermediate-ca
openssl genrsa -out int-ca-priv.pem 4096

openssl req -new \
	-key int-ca-priv.pem \
	-out int-ca-csr.pem \
	-subj "/CN=intermediate-ca"

openssl x509 -req \
	-in int-ca-csr.pem \
	-CA ca-cert.pem \
	-CAkey ca-priv.pem \
	-CAcreateserial \
	-out int-ca-cert.pem \
	-days 3650 \
	-copy_extensions none \
	-extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")

rm -f int-ca-csr.pem ca-cert.srl

# code-signing key
openssl ecparam -name secp384r1 -genkey -noout -out signing-key.pem

openssl req -new \
	-key signing-key.pem \
	-out signing-key-csr.pem \
	-subj "/CN=signing-key"

openssl x509 -req \
	-in signing-key-csr.pem \
	-CA int-ca-cert.pem \
	-CAkey int-ca-priv.pem \
	-CAcreateserial \
	-out signing-key-cert.pem \
	-days 3650 \
	-copy_extensions none \
	-extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n")

rm -f signing-key-csr.pem int-ca-cert.srl

openssl ec -in signing-key.pem -pubout -out signing-key-pub.pem
