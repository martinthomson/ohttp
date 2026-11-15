# Image for https://github.com/anthropics/oss-scanner. Everything the scanner may need must be fetched and built here;
# the scan itself runs offline.
FROM rust:1-trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev gyp ninja-build python-is-python3 zlib1g-dev git \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# pre-commit runs `cargo +stable` and `cargo +<rust-version>`, so install both under those names.
COPY Cargo.toml /tmp/Cargo.toml
RUN MSRV=$(sed -ne 's/^rust-version *= *"//;T;s/".*$//;p' /tmp/Cargo.toml) \
    && rustup toolchain install stable "$MSRV" --profile minimal --component clippy,rustfmt \
    && rustup default stable \
    && rm /tmp/Cargo.toml

# NSS and NSPR sources, as in .github/workflows/check.yml. ohttp's build script runs NSS's build.sh
# itself (into /dist), so the cargo builds below compile NSS and later builds reuse that output.
ARG NSS_REF=master
ARG NSPR_REF=main
RUN git clone --depth 1 --branch "$NSPR_REF" https://github.com/mozilla/nspr /nspr \
    && git clone --depth 1 --branch "$NSS_REF" https://github.com/mozilla/nss /nss
ENV NSS_DIR=/nss \
    LD_LIBRARY_PATH=/dist/Debug/lib

COPY . /src
WORKDIR /src
# Image layers keep whole-second mtimes only; match that so cargo's prebuilt fingerprints stay fresh.
RUN find /src -exec touch -h -d "@$(date +%s)" {} +
# pre-commit needs `git rev-parse`; the scanner may run as a different user than the one that owns /src.
RUN git config --system --add safe.directory '*'

# Fetch every dependency and prebuild what pre-commit builds, for both HPKE backends and both
# toolchains, because the agent has only 2 CPUs. Cargo.lock is not committed, so make one here.
ENV CARGO_NET_OFFLINE=true
RUN CARGO_NET_OFFLINE=false cargo generate-lockfile \
    && CARGO_NET_OFFLINE=false cargo fetch \
    && MSRV=$(sed -ne 's/^rust-version *= *"//;T;s/".*$//;p' Cargo.toml) \
    && for v in stable "$MSRV"; do \
         cargo "+$v" build --workspace --all-targets -F stream \
         && cargo "+$v" clippy --tests -F stream \
         && cargo "+$v" test --no-run -F stream \
         && cargo "+$v" build --workspace --all-targets --no-default-features --features nss,http,client,server,stream \
         && cargo "+$v" clippy --tests --no-default-features --features nss,http,client,server,stream \
         && cargo "+$v" test --no-run --no-default-features --features nss,http,client,server,stream \
         || exit 1; \
       done

# Check the image works, but don't fail the build on check failures.
RUN timeout 7200 bash .oss-scanner/ci.sh || echo "WARNING: .oss-scanner/ci.sh reported failures"
