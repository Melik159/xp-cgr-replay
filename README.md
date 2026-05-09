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

### 5. Wallet derivation

cd wallet
python3 wallet_proof.py sample01/prng_log_excerpt.jsonl

Expected:

RAND==SECRET:   OK
WIF uncomp:     OK
P2PKH uncomp:   OK

This validates the deterministic derivation from the captured RAND_bytes
output to the corresponding Bitcoin private-key encoding and P2PKH address.

------------------------------------------------------------------

### Notes

- This repository is intentionally minimal and focuses on bit-exact reproducibility
- Large-scale campaigns and extended pool attribution are not included
- All observations correspond to Windows XP SP3

Open component:

seedbase_after → state20

------------------------------------------------------------------

### ssleay

The `ssleay/` module validates the OpenSSL 0.9.8 `ssleay_rand_bytes()`
post-stir output path. The replay starts from an anonymized
`state_after_stir` trace, selects the state window at index `240`,
recomputes each SHA-1 digest independently, verifies the XOR state update,
and reconstructs the final 32-byte `RAND_bytes` output.

------------------------------------------------------------------

### Campaigns

The `campaigns/` directory contains public replay artifacts derived from larger
WinDbg/KD trace campaigns.

Each campaign is intentionally narrow: it validates one experimentally isolated
relation and should not be read as a complete replay of Windows XP
`CryptGenRandom`.

Current included campaigns:

- `seed2state_v5_roundrobin/` — validates the downstream
  KSecDD/ADVAPI/SystemFunction036/rsaenh `aux20` path. It observes the KSecDD
  `RC4_2` 0x100-byte output as an ADVAPI-side IOCTL buffer, validates the
  ADVAPI32 eight-state RC4 round-robin manager, replays non-zero ADVAPI32 RC4
  PRGA calls from captured states, correlates PRGA output with
  `SystemFunction036`, and correlates `SystemFunction036` output with
  `rsaenh aux20`.

- `seed2state_v17_1_precise_ioctl_outbuf/` — provides a tighter ADVAPI-side
  validation of the IOCTL-output-buffer to RC4-state segment. It starts from
  captured ADVAPI IOCTL `0x390008` `outbuf[0x100]` samples, verifies that
  `outbuf[0:256]` reproduces the corresponding RC4 KSA states, replays useful
  PRGA20 calls from captured states, checks the post-PRGA state evolution, and
  includes negative controls on mutated IOCTL buffers and mutated PRGA states.

Validated relation for `seed2state_v5_roundrobin/`:

```text
KSecDD RC4_2 output
→ ADVAPI32 IOCTL buffer
→ ADVAPI32 eight-state RC4 manager
→ ADVAPI32 RC4 PRGA
→ SystemFunction036 output20
→ rsaenh aux20
```

Validated relation for `seed2state_v17_1_precise_ioctl_outbuf/`:

```text
captured ADVAPI IOCTL 0x390008 outbuf[0x100]
→ RC4 KSA from outbuf[0:256]
→ ADVAPI RC4 state
→ useful PRGA20 replay
→ SystemFunction036 output20
```

The V17.1 artifact strengthens the ADVAPI-side part of the previous
round-robin result by checking the binary samples directly and by adding
negative controls:

```text
mutated IOCTL outbuf → KSA match rejected
mutated PRGA state   → PRGA replay rejected
```

Together, these campaigns validate the downstream `G_aux` / ADVAPI-to-`aux20`
branch from captured ADVAPI RC4 material to `SystemFunction036 output20` and,
in the V5 campaign, to `rsaenh aux20`.

They do not close:

```text
seedbase_after / persistent provider state → state20
```

They also do not claim:

```text
complete Windows XP CryptGenRandom reconstruction
complete seedbase_after → provider_state → state20 replay
complete entropy assessment
practical attack against Bitcoin or historical keys
```

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
