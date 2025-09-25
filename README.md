# Oblivious HTTP

This is a rust implementation of [Oblivious
HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
and the supporting [Binary HTTP
Messages](https://www.rfc-editor.org/rfc/rfc9292.html).

The `ohttp` crate uses either [hpke](https://github.com/rozbb/rust-hpke) or
[NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html) for
cryptographic primitives.


## Using

The API documentation is currently sparse, but the API is fairly small and
descriptive.

The `bhttp` crate has the following features:

- `http` enables parsing and generation of binary HTTP messages.
  This is disabled by default.

- `stream` enables stream processing (presently just reading)
  of binary HTTP messages.  This is disabled by default until it stabilizes.

The `ohttp` crate has the following features:

- `client` enables the client-side processing of oblivious HTTP messages:
  encrypting requests and decrypting responses.  This is enabled by default.

- `server` enables the server-side processing of oblivious HTTP messages:
  decrypting requests and encrypting responses.  This is enabled by default.

- `rust-hpke` selects the [hpke](https://github.com/rozbb/rust-hpke) crate for
  HPKE encryption.  This is enabled by default and cannot be enabled at the same
  time as `nss`.

- `nss` selects
  [NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html).  This is
  disabled by default and cannot be enabled at the same time as `rust-hpke`.

- `stream` enables stream processing (presently just reading)
  of [chunked Oblivious HTTP messages](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-chunked-ohttp).
  This is disabled by default until it stabilizes.


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
`ohttp-server` respectively.  The server acts as both an Oblivious Gateway
Resource and a Target Resource.  You will need to provide your own relay.
Though a direct request to the server will demonstrate that things are working,
the server sees your IP address.


## Getting and Building With NSS

The build setup is a little tricky, mostly because building NSS is a bit fiddly.

First, you need a machine capable of [building NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Building).

<details>
<summary>For those on Ubuntu/Debian...</summary>
The minimal set of prerequisites for an x64 build
(and the later steps) can be installed using:

```sh
sudo apt-get install \
  ca-certificates coreutils curl git make mercurial \
  build-essential clang llvm libclang-dev lld \
  gyp ninja-build pkg-config zlib1g-dev
```

</details>


<details>
<summary>For those on Arch...</summary>
The minimal set of prerequisites for an x64 build
(and the later steps) can be installed using:

```sh
sudo apk add mercurial gyp ca-certificates coreutils \
  curl git make mercurial clang llvm lld ninja-build
```

</details>

You then need to clone this repository, the NSS repository, and the NSPR
repository.  I generally put them all in the same place.

```sh
cd $workspace
git clone https://github.com/martinthomson/ohttp ./ohttp
git clone https://github.com/nss-dev/nss ./nss
# or
# hg clone https://hg.mozilla.org/projects/nss ./nss
hg clone https://hg.mozilla.org/projects/nspr ./nspr
```

The build then needs to be told about where to find NSS.  The runtime also needs
to be told where to find NSS libraries. This helps avoid linking with any NSS
version you might have installed in the OS, which won't work (yet).

```sh
export NSS_DIR=$workspace/nss
export LD_LIBRARY_PATH=$workspace/dist/Debug/lib
```

On a Mac, use `DYLD_LIBRARY_PATH` instead of `LD_LIBRARY_PATH`.
If you are building with `--release`, the path includes "Release" rather than "Debug".

Then you should be able to build and run tests:

```sh
cd $workspace
cargo build -F nss,client,server,http --no-default-features
cargo test -F nss,client,server,http --no-default-features
```


## Contributing

Contributions are welcome provided you are respectful of others in your
interactions.

Continuous integration runs all tests plus `cargo fmt -- --check` and `cargo
clippy --tests`.

There is a pre-commit script that you can link to `.git/hooks/pre-commit` that
runs `cargo fmt` on all commits.  Just run `./pre-commit install` to have it
install itself.

## Minnimum Supported Rust Version (MSRV)

`ohttp` and `bhttp` should compile on Rust 1.63.0.
