#!/usr/bin/env bash

if [[ "$#" -ne 1 ]]; then
   echo "Usage: $0 <version>" 1>&2
   exit 2
fi

trap 'echo "*** release failed"; exit 1' ERR

v="${1#v}"
find . -name Cargo.toml -exec sed -i -e '/^\[package\]/,/^\[/{s/^version = ".*"/version = "'"$v"'"/;}' {} \+
find . -name Cargo.toml -exec git commit -m "Update version to $v" {} \+
git tag -m "Tag release $v" "v$v"
