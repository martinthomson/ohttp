#!/usr/bin/env bash

if [[ "$#" -ne 1 ]]; then
   echo "Usage: $0 <version>" 1>&2
   exit 2
fi

set -e

find . -name Cargo.toml -exec sed -i -e '/^\[package\]/,/^\[/{s/^version = ".*"/version = "'"$1"'"/;}' {} \+
find . -name Cargo.toml -exec git commit -m "Update version to $1" {} \+
git tag -m "Tag release $1" "v$1"
