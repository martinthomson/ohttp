FROM rust:1.67 as builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq \
ca-certificates coreutils curl git make mercurial \
build-essential clang llvm libclang-dev lld \
gyp ninja-build pkg-config zlib1g-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path ohttp-server

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates openssl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/ohttp-server /usr/local/bin/ohttp-server
COPY ./ohttp-server/ca.sh /usr/local/bin
COPY --chmod=755 ./docker/run.sh .
CMD ["./run.sh"]
