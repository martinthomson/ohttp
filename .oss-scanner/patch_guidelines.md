# How we would like patches made

## Size and scope of a fix

- Fix the root cause, minimally, where the input is first parsed or checked. Also fix defects in the
  code path the fix touches; name similar issues elsewhere in the report instead.
- Follow the spec (see `threat_model.md`), including SHOULDs. Return an error, reusing an existing
  `Error` variant where one fits; never panic on untrusted data. Do not weaken assertions; handle
  the condition that trips them.
- Work with both HPKE backends (`nss` and `rust-hpke`), with and without `stream`, with every KEM,
  KDF and AEAD the crate supports, and with any RFC-compliant peer.
- No cost on the normal path, and no new dependencies unless unavoidable; say so if so.
- One root cause per patch.

## Code style

- Follow the surrounding code; reuse existing helpers and terminology. Stable Rust at the workspace
  `rust-version`.
- Fix lints by changing code, not with `#[allow]` or `#[expect]`.
- Default to no new comment; at most one line where the code cannot speak for itself. Keep existing
  comments.
- Format with `cargo fmt -- --config imports_granularity=Crate,group_imports=StdExternalCrate`;
  `bash .oss-scanner/ci.sh` must pass.

## Tests

- Add a regression test that fails without the fix and passes with it, in the existing test module
  for the area (`#[cfg(test)] mod test` in the module, or `bhttp/tests/test.rs`), using the helpers
  there.
- The test must pass with both `cargo test -F stream` and
  `cargo test --no-default-features --features nss,http,client,server,stream`.
- Deterministic: build inputs from fixed bytes and assert exact values or error variants.

## Branch and commit message

- Against `main`. A short imperative subject, prefixed with the crate where that helps, e.g.
  `ohttp: reject truncated chunked responses`, plus at most one short body sentence. No exploit
  details.
