# Windows XP CryptGenRandom: Block-Level Replay Artifact

This repository reorganizes the retained experimental material for:

> *An Empirical Analysis of CryptGenRandom in Windows XP SP3 and Its
> Historical Relevance to Bitcoin 0.1.5*

The artifact validates isolated relations in eight blocks. It does not claim
an end-to-end reconstruction of Windows XP `CryptGenRandom`, a complete
entropy assessment, or an attack against Bitcoin keys.

## Quick validation

Requirements: Python 3.10 or later and a standard Unix-like command-line
environment. The validation code uses only the Python standard library.

```bash
python3 validate.py
```

Expected summary:

```text
PASS=18 PARTIAL=1 FAIL=0
OVERALL=PASS_WITH_DECLARED_PARTIAL
```

V24 is the declared partial result. Its retained material replays 16 RC4 KSA
calls, 16 RC4 PRGA calls, and eight KSecDD after/pre-return equalities, but it
does not contain a trustworthy full 256-byte ADVAPI output-buffer capture.

List or select blocks:

```bash
python3 validate.py --list
python3 validate.py --block 03-kernel-transport
python3 validate.py --block 05-provider-state --json /tmp/provider-state.json
```

Each directory under `blocks/` also contains an English `validate.py` launcher.

## Repository layout

```text
blocks/                    block-oriented entry points and documentation
docs/                      campaign map, claim boundaries, and provenance
evidence/components/       small standalone component replays
evidence/campaigns/        normalized campaign evidence
validation/                fail-closed validation implementation
validate.py                global launcher
SHA256SUMS                 integrity manifest for the reorganized artifact
SOURCE_FILE_MAP.tsv        source-to-reorganized content provenance
```

Every normalized campaign uses the same top-level vocabulary:

```text
capture/       retained raw, redacted, or reduced trace material when available
samples/       binary or structured observations used by validation
reports/       retained historical reports; never trusted as the sole verdict
provenance/    summaries derived from omitted collection logs
tools/         original parsers and replay tools
README.md      new scope and claim statement
```

Directories that do not apply to a campaign are omitted.

## Validation blocks

| Block | Relation | Result |
|---|---|---|
| 01 | captured Windows `RAND_poll` inputs | PASS |
| 02 | kernel pool/VLH to `seedbase_after` | PASS |
| 03 | KSecDD/NewGenRandom/ADVAPI transport | PASS, with V24 PARTIAL |
| 04 | ADVAPI RC4 and `SystemFunction036` | PASS |
| 05 | `rsaenh` provider state transitions | PASS |
| 06 | XOR, SHA-1/FIPS-style, and RC4 primitives | PASS |
| 07 | OpenSSL post-stir byte generation | PASS |
| 08 | OpenSSL output to Bitcoin wallet values | PASS |

The blocks are validation boundaries, not a claim that one retained execution
links every block to the next. See [Claim Boundaries](docs/CLAIM_BOUNDARIES.md).

## Evidence policy

- No experimental capture or measured value was synthesized for this
  reorganization.
- The 1,144 retained source data and script files have the same SHA-256 content
  multiset as the selected files in the original directory.
- Old decorative shell launchers, stale nested manifests, Python caches,
  backup files, and old README files were excluded and replaced.
- Historical reports are retained for provenance, but current verdicts are
  recomputed from logs, event streams, and binary samples whenever possible.
- Missing raw collection logs are stated explicitly.

## Main open boundary

The retained evidence does not close a single-run end-to-end relation:

```text
kernel seedbase_after
  -> KSecDD / ADVAPI / SystemFunction036 provenance
  -> rsaenh provider state20
  -> OpenSSL stirring inputs
  -> wallet key
```

V29 closes the composed provider-side transition for one captured execution,
not the complete upstream Windows-to-provider chain.

## License

See [LICENSE](LICENSE). The retained license permits academic research,
verification, and educational use, but restricts redistribution,
modification, commercial use, and incorporation into other artifacts.
