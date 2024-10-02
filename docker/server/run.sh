#!/bin/bash

is_valid_url() {
    local url="$1"

    # Regular expression to validate the URL
    local regex='^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$'

    if [[ $url =~ $regex ]]; then
        return 0
    else
        return 1
    fi
}

if [[ -z ${TARGET} ]]; then
  echo "No TARGET defined"
  exit 1
fi

if is_valid_url $TARGET; then 
  CMD="RUST_LOG=info /usr/local/bin/ohttp-server --target $TARGET"
else
  echo "TARGET is not a valid URL"
  exit 1
fi

if [[ -z ${INSTANCE_SPECIFIC_KEY} ]]; then
  CMD="$CMD --attest"
fi

if [[ -n ${INJECT_HEADERS} ]]; then 
  CMD="$CMD -i ${INJECT_HEADERS}"
fi

if [[ -n ${MAA_URL} ]]; then 
  if is_valid_url $MAA_URL; then 
    CMD="$CMD --maa-url ${MAA_URL}"
  else 
    echo "MAA_URL is not a valid URL"
    exit 1
  fi
fi

if [[ -n ${KMS_URL} ]]; then 
  if is_valid_url $KMS_URL; then 
    CMD="$CMD --kms-url ${KMS_URL}"
  else 
    echo "KMS_URL is not a valid URL"
    exit 1
  fi
fi

# Run OHTTP server
echo "Running $CMD..."
eval $CMD