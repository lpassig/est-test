#!/bin/bash
#
# A very rough smoke test script to get a Vault EST server up and running
#

set -eux

START_VAULT="yes"

TMPDIR=/var/aziot/certs
CERTDIR="${TMPDIR}"
mkdir -p "${CERTDIR}"

export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_TOKEN="devroot"
export VAULT_CACERT="${CERTDIR}vault-ca.pem"
export SSL_CERT_FILE="${VAULT_CACERT}"
export EST_USER="estuser"
export EST_PASS="estpass"

if [ "${START_VAULT}" == "yes" ]; then
    # Cleanup old instance
    if kill "$(pgrep 'vault')"; then
      while nc localhost 8200; do sleep 1; done
      sleep 1
    fi
    rm -f "${TMPDIR}/vault.log"

    vault server -dev-tls -dev-root-token-id="${VAULT_TOKEN}" -log-level=debug -dev-tls-cert-dir="${CERTDIR}" -dev-tls-san=host.docker.internal 2> "${TMPDIR}/vault.log" &
    while ! nc -w 1 -d localhost 8200; do sleep 1; done
fi

####
# Setup root mount
####
vault secrets enable -path=pki -default-lease-ttl=8760 pki

vault write pki/config/urls \
     issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
     crl_distribution_points="${VAULT_ADDR}/v1/pki/crl" \
     ocsp_servers="${VAULT_ADDR}/v1/pki/ocsp"

vault write -field=certificate pki/root/generate/internal \
    common_name=root-example.com \
    ttl=8760h > "${TMPDIR}/CA_cert.crt"

####
# Setup intermediary mount
####
vault secrets enable -path=pki_int -default-lease-ttl=4380 pki

vault write pki_int/config/urls \
     issuing_certificates="${VAULT_ADDR}/v1/pki_int/ca" \
     crl_distribution_points="${VAULT_ADDR}/v1/pki_int/crl" \
     ocsp_servers="${VAULT_ADDR}/v1/pki_int/ocsp"

####
# Import root CA into intermediary mount
####
vault write -format=json /pki_int/issuers/import/cert \
     pem_bundle="@${TMPDIR}/CA_cert.crt" \
     | jq -r '.data.imported_issuers[0]' > "${TMPDIR}/root-issuer-id.txt"

ROOT_ISSUER_ID=$(cat "${TMPDIR}/root-issuer-id.txt")

curl -X PATCH \
     -H 'Content-Type: application/merge-patch+json' \
     -H "X-Vault-Token: ${VAULT_TOKEN}" \
     -d '{"issuer_name": "root-ca"}' \
     "${VAULT_ADDR}/v1/pki_int/issuer/${ROOT_ISSUER_ID}"

vault list -detailed -format=json pki_int/issuers

####
# Generate and import signed intermediary CA into intermediary mount
####
vault write -format=json pki_int/intermediate/generate/internal \
     common_name="example.com Intermediate Authority" \
     | jq -r '.data.csr' > "${TMPDIR}/pki_intermediate.csr"

vault write -format=json pki/root/sign-intermediate csr="@${TMPDIR}/pki_intermediate.csr" \
     ttl="43800h" \
     | jq -r '.data.certificate' > "${TMPDIR}/intermediate.cert.pem"

vault write -format=json pki_int/intermediate/set-signed \
     certificate=@${TMPDIR}/intermediate.cert.pem \
     | jq -r '.data.imported_issuers[0]' > "${TMPDIR}/intermediary-issuer-id.txt"

INT_ISSUER_ID=$(cat ${TMPDIR}/intermediary-issuer-id.txt)

curl -X PATCH \
     -H 'Content-Type: application/merge-patch+json' \
     -H "X-Vault-Token: ${VAULT_TOKEN}" \
     -d '{"issuer_name": "intermediary-ca"}' \
     "${VAULT_ADDR}/v1/pki_int/issuer/${INT_ISSUER_ID}"

###
# Setup a cert-auth mount with our CA
###

cat > "${TMPDIR}/est-policy" <<EOP
path "pki_int/est/*" {
  capabilities=["read", "update", "create"]
}
path "pki_int/roles/est-clients/est/*" {
  capabilities=["read", "update", "create"]
}
EOP
vault policy write access-est "${TMPDIR}/est-policy"

vault auth enable cert
vault write auth/cert/certs/est-ca \
    display_name="EST Client CA" \
    token_policies="access-est" \
    certificate="@${TMPDIR}/intermediate.cert.pem" \
    token_type="batch" \
    allowed_common_names="client.docker.internal" 

CERT_ACCESSOR=$(vault read -field=accessor sys/auth/cert)

###
# Setup a userpass mount
###
vault auth enable userpass
vault write auth/userpass/users/${EST_USER} \
  password=${EST_PASS} \
  token_policies="access-est" \
  token_type="batch"

UP_ACCESSOR=$(vault read -field=accessor sys/auth/userpass)

###
# Setup a role for est-clients
###
vault write pki_int/roles/est-clients \
     allowed_domains="docker.internal,local" \
     allow_subdomains=true \
     no_store="false" \
     max_ttl="720h" \
     require_cn="false"

vault write pki_int/config/est -<<EOC
{
  "enabled": true,
  "default_mount": true,
  "default_path_policy": "sign-verbatim",
  "label_to_path_policy": {
    "test-label": "role:est-clients",
    "sign-all": "sign-verbatim"
  },
  "authenticators": {
    "cert": {
      "accessor": "${CERT_ACCESSOR}"
    },
    "userpass": {
      "accessor": "${UP_ACCESSOR}"
    }
  }
}
EOC

vault secrets tune \
  -allowed-response-headers="Content-Transfer-Encoding" \
  -allowed-response-headers="Content-Length" \
  -allowed-response-headers="WWW-Authenticate" \
  -delegated-auth-accessors="${CERT_ACCESSOR}" \
  -delegated-auth-accessors="${UP_ACCESSOR}" \
  pki_int

vault write -format=json pki_int/issue/est-clients \
  common_name="client.docker.internal" &> "${TMPDIR}/est-client.json"

jq -r .data.certificate "${TMPDIR}/est-client.json" > "${TMPDIR}/est-client.cert"
jq -r .data.private_key "${TMPDIR}/est-client.json" > "${TMPDIR}/est-client.key"

cat <<EOF
##################################################
##################################################
##################################################

To interact with the EST server set the following

export VAULT_ADDR="${VAULT_ADDR}"
export VAULT_TOKEN="${VAULT_TOKEN}"
export VAULT_CACERT="${VAULT_CACERT}"
export EST_USER="${EST_USER}"
export EST_PASS="${EST_PASS}"

You can use the GlobalSign EST client (https://github.com/globalsign/est/)
against this Vault server

 - The default EST location is setup for sign-verbatim
 - An EST label of 'test-label' is setup for role est-clients

\$ estclient cacerts -insecure -server localhost:8200
\$ estclient enroll -insecure -server localhost:8200 -user \$EST_USER -pass \$EST_PASS -key ${TMPDIR}/est-client.key
EOF
