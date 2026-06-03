#!/usr/bin/env bash
set -euo pipefail

# Demo PKI for internal mTLS.
# Generates a local CA, Envoy client certificate, and backend server certificates.
# Output goes to pki/certs/ and must not be committed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/pki/certs"
DAYS_CA="${DAYS_CA:-365}"
DAYS_LEAF="${DAYS_LEAF:-30}"

mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

write_ext() {
  local name="$1"
  local type="$2"
  local dns="$3"
  local file="${CERT_DIR}/${name}.ext"

  if [[ "${type}" == "server" ]]; then
    cat > "${file}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${dns}
EOF
  else
    cat > "${file}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:${dns}
EOF
  fi
}

issue_cert() {
  local name="$1"
  local type="$2"
  local dns="$3"

  openssl genrsa -out "${CERT_DIR}/${name}.key" 2048
  openssl req -new \
    -key "${CERT_DIR}/${name}.key" \
    -out "${CERT_DIR}/${name}.csr" \
    -subj "/CN=${dns}"
  write_ext "${name}" "${type}" "${dns}"
  openssl x509 -req \
    -in "${CERT_DIR}/${name}.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/${name}.crt" \
    -days "${DAYS_LEAF}" \
    -sha256 \
    -extfile "${CERT_DIR}/${name}.ext"
}

if [[ ! -f "${CERT_DIR}/ca.crt" || ! -f "${CERT_DIR}/ca.key" ]]; then
  openssl genrsa -out "${CERT_DIR}/ca.key" 4096
  openssl req -x509 -new -nodes \
    -key "${CERT_DIR}/ca.key" \
    -sha256 \
    -days "${DAYS_CA}" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/CN=zero-trust-demo-root-ca"
fi

issue_cert "envoy-client" "client" "envoy"
issue_cert "user-service" "server" "user-service"
issue_cert "resource-service" "server" "resource-service"
issue_cert "admin-service" "server" "admin-service"

rm -f "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.ext "${CERT_DIR}/ca.srl"
chmod 600 "${CERT_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.crt

cat <<EOF
Generated demo mTLS certificates in ${CERT_DIR}

CA:
  ${CERT_DIR}/ca.crt

Envoy client cert:
  ${CERT_DIR}/envoy-client.crt
  ${CERT_DIR}/envoy-client.key

Backend server certs:
  ${CERT_DIR}/user-service.crt
  ${CERT_DIR}/resource-service.crt
  ${CERT_DIR}/admin-service.crt
EOF
