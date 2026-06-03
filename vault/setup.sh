#!/usr/bin/env bash
set -euo pipefail

# Configure demo Vault PKI. Assumes Vault is reachable and VAULT_TOKEN is set.
# With docker compose dev Vault:
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=root
#   bash vault/setup.sh

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

if [[ -z "${VAULT_TOKEN:-}" ]]; then
  echo "VAULT_TOKEN is required. For local demo: export VAULT_TOKEN=root" >&2
  exit 1
fi

vault_cmd() {
  if command -v vault >/dev/null 2>&1; then
    VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_TOKEN}" vault "$@"
  else
    docker compose exec -T \
      -e VAULT_ADDR="http://127.0.0.1:8200" \
      -e VAULT_TOKEN="${VAULT_TOKEN}" \
      vault vault "$@"
  fi
}

mkdir -p pki/certs

vault_cmd secrets enable -path=pki pki 2>/dev/null || true
vault_cmd secrets tune -max-lease-ttl=8760h pki

vault_cmd write -field=certificate pki/root/generate/internal \
  common_name="zero-trust-demo-root-ca" \
  ttl=8760h > pki/certs/vault-ca.crt

vault_cmd write pki/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"

vault_cmd write pki/roles/backend-service \
  allowed_domains="user-service,resource-service,admin-service" \
  allow_bare_domains=true \
  allow_subdomains=false \
  max_ttl=48h \
  server_flag=true \
  client_flag=false

vault_cmd write pki/roles/envoy-client \
  allowed_domains="envoy" \
  allow_bare_domains=true \
  allow_subdomains=false \
  max_ttl=48h \
  server_flag=false \
  client_flag=true

echo "Vault PKI configured. Demo OpenSSL certs still live in pki/certs for Compose mTLS."
