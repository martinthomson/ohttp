#!/bin/bash

# Obtain KMS service certificate
curl -s -k https://acceu-aml-504.confidential-ledger.azure.com/node/network | jq -r .service_certificate > service_cert.pem

# Get list of public keys
curl --cacert service_cert.pem https://acceu-aml-504.confidential-ledger.azure.com/listpubkeys > keys.json

# Run OHTTP client
/usr/local/bin/ohttp-client --trust ./usr/local/bin/ca.crt \
  'https://localhost:9443/score' -i ./examples/request.txt \
  
