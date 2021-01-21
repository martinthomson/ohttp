# Oblivious HTTP

This is a rust implementation of [Oblivious
HTTP](https://unicorn-wg.github.io/oblivious-http/draft-thomson-http-oblivious.html)
and the supporting [Binary HTTP Messages](https://unicorn-wg.github.io/oblivious-http/draft-thomson-http-binary-message.html).

This uses [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)
for cryptographic primitives.  The support for HPKE in NSS is currently
experimental, so you will have to build NSS in order to use the `ohttp` crate.


## Using

The API documentation is currently sparse, but the API is fairly small and
descriptive.

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


## Getting and Building

The build setup is a little tricky, mostly because building NSS is a bit fiddly.

First, you need a machine capable of [building
NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Building).
For those on Ubuntu/Debian, the minimal set of prerequisites for an x64 build
(and the later steps) can be installed using:

```sh
sudo apt-get install \
  ca-certificates coreutils curl git make mercurial \
  build-essential clang llvm libclang-dev lld \
  gyp ninja-build pkg-config zlib1g-dev
```

You then need to clone this repository, the NSS repository, and the NSPR
repository.  I generally put them all in the same place.

```sh
cd $workspace
git clone https://github.com/martinthomson/ohttp ./ohttp
git clone https://github.com/nss-dev/nss ./nss
# or
# hg clone https://hg.mozilla/org/projects/nss ./nss
hg clone https://hg.mozilla/org/projects/nspr ./nspr
```

The build then needs to be told about where to find NSS.  The runtime also needs
to be told where to find NSS libraries. This helps avoid linking with any NSS
version you might have installed in the OS, which won't work (yet).

```sh
export NSS_DIR=$workspace/nss
export LD_LIBRARY_PATH=$workspace/dist/Debug/lib
```

You might need to tweak this.  On a Mac, use `DYLD_LIBRARY_PATH` instead of
`LD_LIBRARY_PATH`.  And if you are building with `--release`, the path includes
"Release" rather than "Debug".

Then you should be able to build and run tests:

```sh
cd $workspace
cargo build
cargo test
```


## Contributing

Contributions are welcome provided you are respectful of others in your
interactions.

Continuous integration runs all tests plus `cargo fmt -- --check` and `cargo
clippy --tests`.

There is a pre-commit script that you can link to `.git/hooks/pre-commit` that
runs `cargo fmt` on all commits.  Just run `./pre-commit install` to have it
install itself.
