# Threat model

## What this project does and where untrusted input enters

This repository implements Oblivious HTTP (OHTTP, RFC 9458), chunked OHTTP
(draft-ietf-ohai-chunked-ohttp) and Binary HTTP (BHTTP, RFC 9292). Firefox and Mozilla's
application-services use the `ohttp` crate as an OHTTP client, with NSS for cryptography (the `nss`
feature, via the `gecko` or `app-svc` features). The `rust-hpke` feature uses the `hpke` crate and
RustCrypto instead. `nss` and `rust-hpke` are mutually exclusive.

The application calling the API is trusted. Everything else is untrusted:

- The key configuration a client is given (`KeyConfig::decode`, `KeyConfig::decode_list`,
  `ClientRequest::from_encoded_config*`). Clients usually fetch it through a relay or other
  intermediary.
- Encapsulated requests a gateway receives (`Server::decapsulate`, `Server::decapsulate_stream`).
  Clients are anonymous by design, so anyone can send these.
- Encapsulated responses a client receives (`ClientResponse::decapsulate` and the streaming
  equivalent). The relay sits on this path.
- BHTTP messages (`bhttp::Message::read_bhttp`, `read_http` and the `stream` reader), which
  applications parse after decapsulation, and which therefore carry whatever the other endpoint
  sent.
- Chunked OHTTP framing: chunk lengths, the final-chunk marker, and truncation.

Attacker positions to consider: a malicious relay (sees and can modify or drop all encapsulated
traffic, and may control the key configuration the client sees), a malicious client sending to a
gateway, and a malicious gateway or target responding to a client.

The spec for a protocol feature is its RFC or, where no RFC exists yet, the latest version of its
Internet-Draft. Differences from a newer draft in wire format or codepoints that the code keeps for
interoperability are not findings.

## Components that matter most / least

- Most important: client-side code paths in `ohttp` (with both `nss` and `rust-hpke`, with and
  without `stream`) and response parsing in `bhttp`, because that is what Firefox ships.
- In scope at the same severity: the NSS bindings and wrappers in `ohttp/src/nss/` and the
  `rust-hpke` backend in `ohttp/src/rh/`, including `unsafe` FFI code.
- In scope but lower priority: server-side (gateway) code paths in `ohttp` and request parsing in
  `bhttp`.
- Out of scope: `ohttp-client`, `ohttp-client-cli`, `ohttp-server`, `bhttp-convert`, `sync-async`,
  `examples`, the `ohttp/build.rs` build script, and anything that needs the
  `unsafe-print-secrets` feature.
- NSS and third-party crates (`hpke`, RustCrypto): in scope only where this code misuses them, or
  where a bug in them is reachable with peer-controlled data. NSS is scanned separately.

## How to exercise it

- `cargo test -F stream` runs the test suite with `rust-hpke`.
- `cargo test --no-default-features --features nss,http,client,server,stream` runs it with NSS.
  `NSS_DIR` points at an NSS checkout in this image, which `ohttp`'s build script builds into
  `/dist`; NSS is prebuilt.
- Both are prebuilt for stable and the MSRV. `bash .oss-scanner/ci.sh` runs all checks.
- Unit tests live in `#[cfg(test)] mod test` in each module (`ohttp/src/lib.rs` has client/server
  round trips, `ohttp/src/stream.rs` the chunked variants, `ohttp/src/config.rs` key configuration
  decoding); BHTTP integration tests are in `bhttp/tests/test.rs`. There are no fuzz targets.

## How you rate severity

We use Mozilla's client ratings for client code paths, refined by the lists below:

- sec-critical and sec-high differ in risk to users, not technically: critical is for issues that
  are exceptionally easy to exploit at scale.
- sec-high: memory corruption reachable by an attacker; disclosure of request or response content;
  anything that lets a relay or gateway link a client's requests to the client or to each other;
  loss of the confidentiality or integrity that OHTTP's encapsulation provides.
- sec-moderate: a sec-high issue that needs an unusual configuration or is limited in scope;
  information that helps an attacker combine it with other bugs; privacy leaks that do not identify
  the user; memory corruption only under out-of-memory conditions that cannot be triggered
  precisely; conditions that can cause parser deadlocks.
- sec-low: issues with a clear security implication that are hard to exploit or very limited in
  scope, including most denial of service.

### Critical or high

- Memory safety issues reachable with attacker-controlled data, including in the NSS FFI code.
- Breaking an OHTTP security property: accepting a modified or truncated encapsulated request or
  response, accepting a truncated chunked message as complete (final-chunk handling), nonce or key
  reuse in HPKE or response encapsulation (RFC 9458, Section 4.4), deriving keys from the wrong
  inputs, using a different suite than the one negotiated, or leaking secrets or plaintext (for
  example through logs or error values without `unsafe-print-secrets`).
- Behaviour that lets a relay or gateway fingerprint or link clients, for example through
  distinguishable handling of attacker-chosen key configurations.
- A reachable `debug_assert!` that guards memory safety or one of the properties above. Tests enable
  debug assertions; release builds do not.

### Low

These should still be reported:

- Denial of service: panics, aborts, infinite loops, and attacker-driven unbounded memory use (for
  example from length fields in BHTTP or chunked OHTTP). A panic without memory corruption is a
  denial of service, not a memory-safety issue.
- Reachable `debug_assert!` failures without the consequences above.
- Issues that require the application to misuse the API.
- Protocol violations without a security impact, including accepting malformed BHTTP.

Issues only reachable in gateway (server) code are sec-moderate at most, except memory corruption.

## Anything to leave alone

- Replay protection for requests: RFC 9458 leaves this to the gateway application.
- Attacker-driven CPU use that ends on its own, unless the fix is trivial.
- Timing side channels in third-party cryptographic code.
