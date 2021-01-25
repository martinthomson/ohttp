#!/bin/bash
cert=server.crt
certPk=server.key
ca=ca.crt
caPk=ca.key

host="${1:-localhost}"
certValidityDays=30
bits=2048

cd "$(dirname "$0")"

# Create CA
trap 'rm -f 01.pem server.csr ca.db ca.db.* ca.srl ca.srl.* ca.key' EXIT
openssl req -newkey rsa:$bits -keyout "${caPk}" -x509 -new -nodes -out "${ca}" \
  -subj "/OU=Unknown/O=Unknown/L=Unknown/ST=unknown/C=AU" -days "${certValidityDays}"

# Create Cert Signing Request
openssl req -new -newkey rsa:$bits -nodes -keyout "${certPk}" -out server.csr \
  -subj "/CN=${host}/C=AU" -addext "subjectAltName = DNS:${host}"

function print_cfg() {
  touch ./ca.db
  echo 01 > ./ca.srl
  echo "[ ca ]
default_ca = CA_default

[ CA_default ]
dir = .
certificate = \$dir
new_certs_dir = \$dir
database = \$dir/ca.db
certificate = \$dir/${ca}
private_key = \$dir/${caPk}
serial = \$dir/ca.srl
name_opt = ca_default
cert_opt = ca_default
default_days = 90
default_md = sha256
preserve = no
policy = policy_lax
copy_extensions = copy
x509_extensions = server_cert

[ policy_lax ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = digitalSignature, keyEncipherment
"
}

# Sign Cert
openssl ca -batch -utf8 -config <(print_cfg) -in server.csr -out "${cert}"

# Print Cert
openssl x509 -in "$cert" -text -noout
