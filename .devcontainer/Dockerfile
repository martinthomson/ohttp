FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq \
ca-certificates coreutils curl git make mercurial \
build-essential clang llvm libclang-dev lld \
gyp ninja-build pkg-config zlib1g-dev libssl-dev

RUN curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y