# Windows XP SP3 CryptGenRandom — Deterministic Replay

This directory contains a deterministic replay artifact for two independently
captured Windows XP SP3 `CryptGenRandom` executions.

The model starts from retained pre-call state and observed source-return buffers
and reproduces the observed 32-byte caller outputs exactly.

## Historical outputs

### Run 1

```text
a37bf2d7c0c473fc92c62f5171adb25cabdb23a5bb9fcc6b3bd733aaeac53ad4
```

### Run 2

```text
73f3bee078d1335c3dda75994b505be400b1b29ecf2443000cf83128dfcd2fd8
```

## Quick validation

Requires Python 3.

```bash
python3 validate_release.py
```

Expected:

```text
PASS historical Run1
PASS historical Run2
PASS Run1 qsi17[20]=ff counterfactual
OVERALL=PASS
```

Individual replay:

```bash
python3 tools/play_cgr.py --run run1
python3 tools/play_cgr.py --run run2
```

Inspect the controllable input ranges:

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

This value is an offline counterfactual produced by the deterministic model.
It is not an independently captured historical Windows XP output.

## Two-run exhaustive multisource validation

The differential campaign was repeated on two independently captured
executions.

| Campaign | Cases | Controlled outputs | Python / Rust / CUDA |
|---|---:|---:|---:|
| Run 1 | 240/240 PASS | 61,440 | 61,440/61,440 exact |
| Run 2 | 240/240 PASS | 61,440 | 61,440/61,440 exact |
| Combined | 480/480 PASS | 122,880 | 122,880/122,880 exact |

Agreement is bit-for-bit across the Python, Rust and CUDA implementations.

The campaigns cover 13 retained source classes across eight KSecDD events,
with representative byte positions and all 256 possible byte values for each
selected position.

Detailed results are under:

```text
validation/run1/
validation/run2/
validation/combined/
```

The multisource verifier and CUDA implementation are under:

```text
multisource/
```

The independent Rust implementation is under:

```text
rust/
```

## Experimental boundary

The claim is deliberately narrower than "all Windows XP entropy was
reconstructed."

The replay begins at:

- retained pre-acquisition / pre-call state; and
- observed source-return buffers consumed by the reconstructed path.

It establishes deterministic replay and controlled counterfactual evaluation
from that boundary to the observed `CryptGenRandom` caller output for the
retained executions.

It does **not** by itself establish:

- the physical provenance of every entropy source;
- an information-theoretic entropy estimate for Windows XP;
- statistical RNG quality;
- byte-level minimality of every retained state component;
- arbitrary-input execution through the original Microsoft provider binary.

No Microsoft binary is included in this artifact.

## Layout

```text
tools/          Python deterministic replay
fixtures/       retained Run1 and Run2 fixtures
validation/     exhaustive campaign results and plots
multisource/    multisource verifier and CUDA implementation
rust/           independent native Rust implementation
```

## Integrity

A SHA-256 manifest is provided as `SHA256SUMS`.

Verify with:

```bash
sha256sum -c SHA256SUMS
```
