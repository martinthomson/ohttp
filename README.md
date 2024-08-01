# Attested Oblivious HTTP

This is a rust implementation of [Oblivious
HTTP](https://www.ietf.org/archive/id/draft-ohai-chunked-ohttp-01.html)
and the supporting [Binary HTTP
Messages](https://www.rfc-editor.org/rfc/rfc9292.html) that supports attestation and chunking. 

The `ohttp` crate uses either [hpke](https://github.com/rozbb/rust-hpke) or
[NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html) for
cryptographic primitives.


## Using

The API documentation is currently sparse, but the API is fairly small and
descriptive.

The `bhttp` crate has the following features:

- `read-bhttp` enables parsing of binary HTTP messages.  This is enabled by
  default.

- `write-bhttp` enables writing of binary HTTP messages.  This is enabled by
  default.

- `read-http` enables a simple HTTP/1.1 message parser.  This parser is fairly
  basic and is not recommended for production use.  Getting an HTTP/1.1 parser
  right is a massive enterprise; this one only does the basics.  This is
  disabled by default.

- `write-http` enables writing of HTTP/1.1 messages.  This is disabled by
  default.

The `ohttp` crate has the following features:

- `client` enables the client-side processing of oblivious HTTP messages:
  encrypting requests and decrypting responses.  This is enabled by default.

- `server` enables the server-side processing of chunked oblivious HTTP messages:
  decrypting requests and encrypting chunked responses.  This is enabled by default.

- `rust-hpke` selects the [hpke](https://github.com/rozbb/rust-hpke) crate for
  HPKE encryption.  This is enabled by default and cannot be enabled at the same
  time as `nss`.

- `nss` selects
  [NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html).  This is
  disabled by default and cannot be enabled at the same time as `rust-hpke`.


## Utilities

The `bhttp-convert` provides a utility that can convert between the HTTP/1.1
message format (`message/http`) and the proposed binary format
(`message/bhttp`).

For example, to view the binary format:

```sh
cargo run --bin bhttp-convert < ./examples/request.txt | xxd
```

Or, to convert to binary and back again:

```sh
cargo run --bin bhttp-convert < ./examples/response.txt | \
  cargo run --bin bhttp-convert -- -d
```

Sample client and server implementations can be found in `ohttp-client` and
`ohttp-server` respectively. The server acts as an Oblivious Gateway
Resource. You will need to provide a Target resource and your own relay.
Though a direct request to the server will demonstrate that things are working,
the server sees your IP address.

## Development Environment

The repo supports development using GitHub Codespaces and devcontainers. 

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=707634300&skip_quickstart=true&machine=premiumLinux&geo=EuropeWest)

## Build and Test

To build docker images for the server and client, and test with a sample target service,
```
make build
make run
```

## Contributing

Contributions are welcome provided you are respectful of others in your
interactions.

Continuous integration runs all tests plus `cargo fmt -- --check` and `cargo
clippy --tests`.

There is a pre-commit script that you can link to `.git/hooks/pre-commit` that
runs `cargo fmt` on all commits.  Just run `./pre-commit install` to have it
install itself.

## Minimum Supported Rust Version (MSRV)

`ohttp` and `bhttp` should compile on Rust 1.70.0.
