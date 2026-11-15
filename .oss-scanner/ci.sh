#!/usr/bin/env bash
# The checks from pre-commit: rustfmt, then clippy and tests with rust-hpke and (because NSS_DIR is set) NSS,
# on both stable and the MSRV.
export RUST_BACKTRACE=1
cd "$(dirname "$0")/.." || exit
exec ./pre-commit all
