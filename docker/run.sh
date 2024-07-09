#!/bin/bash

# Generate certificate for TLS
/usr/local/bin/ca.sh

# Run OHTTP server
/usr/local/bin/ohttp-server --certificate /usr/local/bin/server.crt --key /usr/local/bin/server.key