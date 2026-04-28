# XP CryptGenRandom Component-Level Replay

This repository provides reproducibility artifacts for the paper:

"An Empirical Analysis of CryptGenRandom in Windows XP SP3 and Its Historical Relevance to Bitcoin 0.1.5"

------------------------------------------------------------------

### Scope

The repository contains executable validation scripts for the closed components
of the CryptGenRandom pipeline identified in the paper.

It supports independent verification of the following relations:

### Kernel entropy processing

pool → VLH → seedbase_after

### Provider-side construction

(state20, aux20) → out40 → CGR output (32 bytes)

### Internal primitives

- SHA-1 compression used in the FIPS-style block
- RC4 key-scheduling algorithm (KSA)

The transition from seedbase_after to state20 is not reproduced in this
repository and remains an open component.

------------------------------------------------------------------

### Repository Structure

- vlh/      — kernel-side VeryLargeHashUpdate replay (pool → seedbase_after)
- provider/ — provider local mixing and high-level output construction
- fips/     — SHA-1 compression replay for the final block
- rc4/      — RC4 KSA validation

------------------------------------------------------------------

### Reproducibility

All scripts operate on captured binary artifacts and reproduce outputs at
byte level.

### 1. VLH kernel phase

cd vlh
python3 validate_vlh_campaign.py

Expected result:

MAPPING_PASS: True
SEED_PASS: True
PASS: True

This validates:
- pool segmentation
- SHA-1-based VLH construction
- exact reconstruction of seedbase_after

------------------------------------------------------------------

### 2. Provider XOR and FIPS-style construction

cd provider
python3 provider_xor_fips_replay.py \
  --state20-file sample01/state20.bin \
  --local-before-file sample01/local_before.bin \
  --src20-file sample01/src20.bin \
  --local-after-file sample01/local_after.bin

This validates the local XOR relation:

local_before XOR src20 = aux20

and the high-level construction:

(state20, aux20) → out40 → CGR output

------------------------------------------------------------------

### 3. FIPS block / SHA-1 compression

cd fips
python3 replay_fips186_block.py \
  sample01/p1_block64.bin \
  sample01/p2_block64.bin \
  --out40-after sample01/out40_after.bin

Expected result:

std_match  : True

This confirms that the final block is reproduced using standard SHA-1
compression.

------------------------------------------------------------------

### 4. RC4 KSA

cd rc4
python3 validate_ksa.py

Expected result:

match       : OK
BIT_EXACT_MATCH: 2048 bits

This validates the RC4 key-scheduling step observed in the provider.

------------------------------------------------------------------

### Notes

- This repository is intentionally minimal and focuses on bit-exact reproducibility
- Large-scale campaigns and extended pool attribution are not included
- All observations correspond to Windows XP SP3

Open component:

seedbase_after → state20

------------------------------------------------------------------

### File Integrity

All binary artifacts used in the experiments are provided with
reference SHA-256 hashes in the file:

SHA256SUMS

These hashes allow byte-level verification of the inputs used in
the reproducibility scripts.

Verification command:

sha256sum -c SHA256SUMS

Note: hashes are provided for integrity and reproducibility purposes
only and do not imply cryptographic security guarantees.

------------------------------------------------------------------

### License

See LICENSE.
