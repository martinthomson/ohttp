FROM rust:1.70 as builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq libssl-dev

WORKDIR /usr/src/ohttp
COPY . .
RUN cargo install --path ohttp-server

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates openssl libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/ohttp-server /usr/local/bin/ohttp-server
COPY ./ohttp-server/ca.sh /usr/local/bin
COPY --chmod=755 ./docker/server/run.sh .
CMD ["./run.sh"]
