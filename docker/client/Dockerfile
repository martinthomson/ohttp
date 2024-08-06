FROM rust:1.70 as builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq \
ca-certificates coreutils curl git make mercurial \
build-essential clang llvm libclang-dev lld \
gyp ninja-build pkg-config zlib1g-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path ohttp-client

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates openssl curl && rm -rf /var/lib/apt/lists/*
COPY ./ohttp-server/ca.sh /usr/local/bin
COPY ./examples ./examples
COPY --from=builder /usr/local/cargo/bin/ohttp-client /usr/local/bin/ohttp-client
COPY --chmod=755 ./docker/client/run.sh .
CMD ["./run.sh"]