#!/bin/bash

# Generate certificate for TLS. Todo: copy ca.crt from the server instead of running ca.sh on the client side to generate server ca.crt.
/usr/local/bin/ca.sh

# Run OHTTP client
/usr/local/bin/ohttp-client --trust ./usr/local/bin/ca.crt \
  'https://localhost:9443/score' -i ./examples/request.txt \
  `curl -s -k https://localhost:9443/discover`
