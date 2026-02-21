#!/usr/bin/env bash
set -e

SUBJ_CA="/C=US/ST=State/L=City/O=TestOrg/CN=TestRootCA"
SUBJ_IM="/C=US/ST=State/L=City/O=TestOrg/CN=TestIntermediateCA"
SUBJ_SRV="/CN=localhost"
SUBJ_CLI="/C=US/ST=State/L=City/O=TestOrg/CN=TestClient"
SUBJ_RSA_CA="/C=US/ST=State/L=City/O=TestOrg/CN=TestRsaRootCA"

EXT_CA="basicConstraints=critical,CA:TRUE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always"
EXT_LEAF="basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer"

# Root CA
openssl ecparam -name prime256v1 -genkey -noout -out root-ca-key.pem
openssl req -new -x509 -sha256 -key root-ca-key.pem -days 3650 -out root-ca.pem -subj "$SUBJ_CA"

# Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out intermediate-ca-key.pem
openssl req -new -sha256 -key intermediate-ca-key.pem -out _im.csr -subj "$SUBJ_IM"
openssl x509 -req -in _im.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out intermediate-ca.pem -days 3650 -sha256 \
  -extfile <(printf "$EXT_CA")
rm _im.csr

# Server leaf cert (signed by root CA)
openssl ecparam -name prime256v1 -genkey -noout -out leaf-server-key.pem
openssl req -new -sha256 -key leaf-server-key.pem -out _srv.csr -subj "$SUBJ_SRV"
openssl x509 -req -in _srv.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out leaf-server.pem -days 3650 -sha256 \
  -extfile <(printf "$EXT_LEAF")
rm _srv.csr

# Client leaf cert (signed by root CA)
openssl ecparam -name prime256v1 -genkey -noout -out leaf-client-key.pem
openssl req -new -sha256 -key leaf-client-key.pem -out _cli.csr -subj "$SUBJ_CLI"
openssl x509 -req -in _cli.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out leaf-client.pem -days 3650 -sha256 \
  -extfile <(printf "$EXT_LEAF")
rm _cli.csr

# Intermediate server cert + chain
openssl ecparam -name prime256v1 -genkey -noout -out intermediate-server-key.pem
openssl req -new -sha256 -key intermediate-server-key.pem -out _imsrv.csr -subj "$SUBJ_SRV"
openssl x509 -req -in _imsrv.csr -CA intermediate-ca.pem -CAkey intermediate-ca-key.pem \
  -CAcreateserial -out intermediate-server.pem -days 3650 -sha256 \
  -extfile <(printf "$EXT_LEAF")
rm _imsrv.csr
cat intermediate-server.pem intermediate-ca.pem > chain.pem

# RSA root CA
openssl req -x509 -newkey rsa:2048 -keyout rsa-root-ca-key.pem -nodes \
  -out rsa-root-ca.pem -sha256 -days 3650 -subj "$SUBJ_RSA_CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectKeyIdentifier=hash"

# RSA server cert
openssl req -newkey rsa:2048 -keyout rsa-leaf-server-key.pem -nodes \
  -out _rsasrv.csr -sha256 -subj "$SUBJ_SRV"
openssl x509 -req -CA rsa-root-ca.pem -CAkey rsa-root-ca-key.pem \
  -in _rsasrv.csr -out rsa-leaf-server.pem -days 3650 -sha256 -CAcreateserial \
  -extfile <(printf "$EXT_LEAF")
rm _rsasrv.csr

# RSA client cert
openssl req -newkey rsa:2048 -keyout rsa-leaf-client-key.pem -nodes \
  -out _rsacli.csr -sha256 -subj "$SUBJ_CLI"
openssl x509 -req -CA rsa-root-ca.pem -CAkey rsa-root-ca-key.pem \
  -in _rsacli.csr -out rsa-leaf-client.pem -days 3650 -sha256 -CAcreateserial \
  -extfile <(printf "$EXT_LEAF")
rm _rsacli.csr
