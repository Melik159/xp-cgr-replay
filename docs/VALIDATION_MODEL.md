# Validation Model

## Fail-closed contract

A check passes only when it verifies both a non-zero expected cardinality and
the claimed byte-level relation. Empty inputs, missing files, incomplete
cycles, subprocess failures, or mismatched bytes produce exit status 1 from
the global launcher.

`PARTIAL` is a declared scientific scope, not a test failure. A partial check
must still validate every relation it reports as present.

## Evidence levels

The documentation uses four evidence levels:

1. **Regenerated from retained capture**: a parser runs against a retained log,
   and regenerated events or samples match the published files.
2. **Replayed from retained samples**: the cryptographic or state transition is
   recomputed from binary samples.
3. **Checked from retained events and samples**: the original capture is
   omitted, but embedded event hashes resolve to retained binaries and the
   local relation is recomputed.
4. **Historical report only**: a report is retained, but the corresponding
   relation cannot be recomputed. Such a report cannot produce `PASS` by
   itself.

## Negative controls

- V17.1 mutates RC4 keys and PRGA states and requires the mutated relations to
  fail.
- The OpenSSL replay uses state index 241 as a negative control for the valid
  index 240 trace.
- Global validators reject zero-cardinality inputs instead of accepting `0/0`.

## Historical tool preservation

Original Python parsers and replay scripts are retained under each evidence
directory. The new validation layer wraps or independently checks them. This
allows the artifact to preserve the original implementation while correcting
old exit-code and launcher behavior without rewriting the captured data.

