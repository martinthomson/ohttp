#!/bin/bash

# Run OHTTP client
/usr/local/bin/ohttp-client \
  'https://localhost:9443/score' -i ./examples/request.txt \
  `curl -s -k https://localhost:9443/discover`
