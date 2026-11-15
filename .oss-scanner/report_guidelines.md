# How we would like reports written

Readers are ohttp maintainers. Be terse: cut prose, never evidence. Do not explain OHTTP, HPKE or
BHTTP, and do not restate the threat model.

## Layout and length

Under one page excluding code, with these sections:

1. **Title**: `<crate>: <what goes wrong>`.
2. **Summary**: the defect, its consequence and its severity under `threat_model.md`, in two or
   three sentences.
3. **Root cause**: the scanned commit, `file:line` of the function that makes the wrong decision,
   and the path from untrusted input to it.
4. **Preconditions**: client and/or gateway; attacker position (relay, client, gateway or target,
   key configuration source); the features needed (`nss` or `rust-hpke`, `stream`, `http`); any
   other non-default setting.
5. **Reproduction**: the test, the command, and the verbatim failure on the scanned commit.
6. **Fix**: what the patch changes and why, and the proposed commit message.

## What every report should state

- Whether release builds, without `debug_assert!`, are affected, and how.
- Whether the finding holds with both the `nss` and `rust-hpke` backends or only one.
- Which claims were verified by running code and which only by reading it.
- The RFC or Internet-Draft (with version) and section a protocol finding rests on. Quote it only if
  certain the text is verbatim.

## Style

- One root cause per report.
- `file:line` for every code claim; quote code rather than describe it. No CVSS vectors or
  disclosure boilerplate.
- RFC and codebase terminology. Label hypotheses as such.
