# Windows XP CryptGenRandom: Blockwise Replay Artifact

This repository reorganizes the retained experimental material for:

> *A Blockwise Empirical Reconstruction of CryptGenRandom in Windows XP SP3
> and Its Observed Relationship to OpenSSL 0.9.8h and Bitcoin 0.1.5*

The repository now contains two complementary artifacts:

1. the original blockwise validation corpus, which validates isolated relations
   across eight analysis blocks; and
2. a deterministic replay artifact for two independently captured Windows XP
   SP3 `CryptGenRandom` executions.

The deterministic replay starts from an explicit observed-input boundary:
retained pre-acquisition state plus observed source-return buffers. From that
boundary, it reproduces the historical 32-byte `CryptGenRandom` caller outputs
exactly and supports controlled counterfactual evaluation.

It does **not** claim a complete physical provenance analysis of every Windows
XP entropy source, a full information-theoretic entropy assessment, arbitrary-
input execution through the original Microsoft provider binary, or an attack
against Bitcoin keys.

## 2026-08-16 deterministic replay update

A new [deterministic replay artifact](deterministic-replay/) extends the
retained evidence beyond the earlier blockwise validation.

For two independently captured Windows XP SP3 executions, the replay starts
from retained pre-acquisition state and observed source-return buffers and
reproduces the historical 32-byte `CryptGenRandom` caller outputs exactly.

An exhaustive multisource differential campaign evaluated 480 source/offset
cases and 122,880 controlled counterfactual outputs across the two captures.

**122,880 / 122,880 outputs matched bit-for-bit across independent Python,
Rust and CUDA implementations.**

Summary:

| Campaign | Cases | Controlled outputs | Python / Rust / CUDA |
|---|---:|---:|---:|
| Run 1 | 240/240 PASS | 61,440 | 61,440/61,440 exact |
| Run 2 | 240/240 PASS | 61,440 | 61,440/61,440 exact |
| Combined | 480/480 PASS | 122,880 | 122,880/122,880 exact |

Historical 32-byte outputs:

```text
Run 1:
a37bf2d7c0c473fc92c62f5171adb25cabdb23a5bb9fcc6b3bd733aaeac53ad4

Run 2:
73f3bee078d1335c3dda75994b505be400b1b29ecf2443000cf83128dfcd2fd8
```

The claim is deliberately limited to the retained experimental boundary. It
does not by itself characterize the physical provenance or information-
theoretic entropy of every Windows XP source, and it does not establish
arbitrary-input execution through the original Microsoft provider binary.

See [`deterministic-replay/README.md`](deterministic-replay/README.md) for the
replay commands, fixtures, counterfactual example, exhaustive validation
results, Rust/CUDA implementations, and SHA-256 manifests.

## Quick validation

### Original blockwise artifact

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

### Deterministic replay artifact

```bash
cd deterministic-replay
python3 validate_release.py
```

Expected:

```text
PASS historical Run1
PASS historical Run2
PASS Run1 qsi17[20]=ff counterfactual
OVERALL=PASS
```

Individual historical replay:

```bash
python3 tools/play_cgr.py --run run1
python3 tools/play_cgr.py --run run2
```

Inspect controllable input ranges:

```bash
python3 tools/play_cgr.py --run run1 --bounds
```

Example controlled counterfactual:

```bash
python3 tools/play_cgr.py \
  --run run1 \
  --set 'ksec:0:qsi17:20=ff'
```

Expected 32-byte output:

```text
0a7eaa389b0365455c0b0c2ef0c99d1e7ed89eda8906e0f2bca2a3778b807b0c
```

This is an offline counterfactual produced by the deterministic model. It is
not an independently captured historical Windows XP output.

## Repository layout

```text
blocks/                    block-oriented entry points and documentation
docs/                      campaign map, claim boundaries, and provenance
evidence/components/       small standalone component replays
evidence/campaigns/        normalized campaign evidence
validation/                fail-closed validation implementation
deterministic-replay/      two-run deterministic CGR replay and validation
validate.py                global launcher for the blockwise artifact
SHA256SUMS                 integrity manifest for the reorganized artifact
SOURCE_FILE_MAP.tsv        source-to-reorganized content provenance
```

The deterministic replay directory contains:

```text
deterministic-replay/
├── tools/          Python deterministic replay and validators
├── fixtures/       retained Run1 and Run2 fixtures
├── validation/     exhaustive campaign results and plots
├── multisource/    multisource verifier and CUDA implementation
├── rust/           independent native Rust implementation
├── README.md
├── SHA256SUMS
└── validate_release.py
```

Every normalized campaign in the original blockwise corpus uses the same
top-level vocabulary:

```text
capture/       retained raw, redacted, or reduced trace material when available
samples/       binary or structured observations used by validation
reports/       retained historical reports; never trusted as the sole verdict
provenance/    summaries derived from omitted collection logs
tools/         original parsers and replay tools
README.md      scope and claim statement
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

The blocks are validation boundaries. They should not be read as a claim that
the original blockwise artifact alone links every block to the next in one
retained execution. See [Claim Boundaries](docs/CLAIM_BOUNDARIES.md).

The newer deterministic replay artifact closes a different and explicitly
defined relation for its two retained executions:

```text
retained pre-acquisition state
  + observed source-return buffers
  -> reconstructed KSecDD / provider transitions
  -> 32-byte CryptGenRandom caller output
```

That closure is specific to the retained replay boundary and does not, by
itself, extend to physical entropy provenance, the full OpenSSL stirring path,
or the final Bitcoin wallet derivation chain.

## Evidence policy

- No experimental capture or measured value was synthesized for this
  reorganization.
- The 1,144 retained source data and script files in the original blockwise
  corpus have the same SHA-256 content multiset as the selected files in the
  original directory.
- Old decorative shell launchers, stale nested manifests, Python caches,
  backup files, and old README files were excluded and replaced.
- Historical reports are retained for provenance, but current verdicts are
  recomputed from logs, event streams, and binary samples whenever possible.
- Missing raw collection logs are stated explicitly.
- The deterministic replay artifact includes no Microsoft `.dll`, `.sys`, or
  `.exe` binaries.
- The deterministic replay artifact includes SHA-256 manifests for integrity
  checking and the complete retained two-run validation results used for the
  published counters.

## Main open boundary

The **complete Windows-to-OpenSSL-to-wallet chain** remains a broader claim than
the deterministic `CryptGenRandom` replay demonstrated in
[`deterministic-replay/`](deterministic-replay/).

The original blockwise artifact does not by itself close the complete relation:

```text
kernel seedbase_after
  -> KSecDD / ADVAPI / SystemFunction036 provenance
  -> rsaenh provider state20
  -> OpenSSL stirring inputs
  -> wallet key
```

The deterministic replay artifact now closes the retained
pre-acquisition/source-return-buffer boundary through the 32-byte
`CryptGenRandom` caller output for two independent captures.

It does **not** establish, as part of that result:

```text
physical entropy provenance
  -> complete entropy quantification
  -> arbitrary-input native Microsoft-provider replay
  -> full OpenSSL stirring reconstruction
  -> wallet-key derivation as one single retained execution
```

V29 remains relevant to the original blockwise corpus: it closes the composed
provider-side transition for one captured execution, not the complete
Windows-to-OpenSSL-to-wallet chain.

## License

See [LICENSE](LICENSE). The retained license permits academic research,
verification, and educational use, but restricts redistribution,
modification, commercial use, and incorporation into other artifacts.
