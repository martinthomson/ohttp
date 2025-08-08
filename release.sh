#!/usr/bin/env bash

if [[ "$#" -ne 1 ]]; then
   echo "Usage: $0 <version>" 1>&2
   exit 2
fi

trap 'echo "*** release failed"; exit 1' ERR

[[ -e .git/hooks/pre-commit ]] || ! echo "pre-commit hook not enabled"
[[ -z "$(git status --short)" ]] || ! echo "uncommitted files"
[[ "$(git rev-parse --abbrev-ref @)" == "main" ]] || ! echo "not on main branch"
[[ "$(git rev-parse --show-toplevel)" == "$(pwd -P)" ]] || ! echo "not in repository directory"

v="${1#v}"
sed -i -e '/^\[workspace\.package\]/,/^\[/{s/^version = ".*"/version = "'"$v"'"/;}' Cargo.toml
git commit -m "Update version to $v" Cargo.toml || \
  echo "--- Version numbers already updated."
git push origin main
git tag -m "Tag release $v" "v$v"
git push origin "v$v"
cargo publish -p ohttp
cargo publish -p bhttp
