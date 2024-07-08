#/bin/bash

# Generate certificate for TLS
/usr/local/bin/ca.sh

# Run OHTTP server
./ohttp-server --certificate ./server.crt --key ./server.key