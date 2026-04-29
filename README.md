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

### Windows entropy-source decoding

randwin trace → decoded Windows / CryptoAPI entropy-source events

### Provider-side construction

(state20, aux20) → out40 → CGR output (32 bytes)

### OpenSSL / SSLeay RAND_bytes path

state_after_stir → SHA-1 digest iterations → RAND_bytes output

### Bitcoin wallet derivation

RAND_bytes output → private-key material → WIF → P2PKH address

### Internal primitives

- SHA-1 compression used in the FIPS-style block
- RC4 key-scheduling algorithm (KSA)

The transition from seedbase_after to state20 is not reproduced in this
repository and remains an open component.

------------------------------------------------------------------

### Repository Structure

- vlh/       — kernel-side VeryLargeHashUpdate replay (pool → seedbase_after)
- randwin/   — decoded Windows entropy-source traces used by OpenSSL RAND_poll
- ssleay/    — OpenSSL 0.9.8 SSLeay RAND_bytes replay from post-stir state
- provider/  — provider local mixing and high-level output construction
- fips/      — SHA-1 compression replay for the final block
- rc4/       — RC4 KSA validation
- wallet/    — RAND_bytes to Bitcoin WIF/P2PKH derivation proof

------------------------------------------------------------------

### Reproducibility

All scripts operate on captured binary or JSON/JSONL artifacts and reproduce
outputs at byte level where applicable.

### 1. VLH kernel phase

```bash
cd vlh
python3 validate_vlh_campaign.py camp01
````

Expected result:

```text
MAPPING_PASS: True
SEED_PASS: True
PASS: True
```

This validates:

* pool segmentation
* SHA-1-based VLH construction
* exact reconstruction of seedbase_after

---

### 2. randwin entropy-source decoder

```bash
cd randwin
python3 decode_randwin_full.py sample01/randwin_full.json --summary
```

The `randwin/` module decodes captured Windows entropy-source material used
around the OpenSSL `RAND_poll` path. It provides structured inspection of
sources such as CryptoAPI/CryptGenRandom, Lanman workstation/server data,
foreground-window and cursor state, heap/process/thread/module enumeration,
performance counters, memory status, and process identifiers.

Additional examples:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --modules
python3 decode_randwin_full.py sample01/randwin_full.json --processes
python3 decode_randwin_full.py sample01/randwin_full.json --threads
python3 decode_randwin_full.py sample01/randwin_full.json --heaps
python3 decode_randwin_full.py sample01/randwin_full.json --memory
python3 decode_randwin_full.py sample01/randwin_full.json --timing
python3 decode_randwin_full.py sample01/randwin_full.json --coherence
```

This validates that the captured `randwin_full.json` files can be decoded
and inspected as structured entropy-source traces rather than opaque blobs.

---

### 3. Provider XOR and FIPS-style construction

```bash
cd provider
python3 provider_xor_fips_replay.py \
  --state20-file sample01/state20.bin \
  --local-before-file sample01/local_before.bin \
  --src20-file sample01/src20.bin \
  --local-after-file sample01/local_after.bin
```

This validates the local XOR relation:

```text
local_before XOR src20 = aux20
```

and the high-level construction:

```text
(state20, aux20) → out40 → CGR output
```

---

### 4. FIPS block / SHA-1 compression

```bash
cd fips
python3 replay_fips186_block.py \
  sample01/p1_block64.bin \
  sample01/p2_block64.bin \
  --out40-after sample01/out40_after.bin
```

Expected result:

```text
std_match  : True
```

This confirms that the final block is reproduced using standard SHA-1
compression.

---

### 5. RC4 KSA

```bash
cd rc4
python3 validate_ksa.py --sample-dir sample01
```

Expected result:

```text
match       : OK
BIT_EXACT_MATCH: 2048 bits
```

This validates the RC4 key-scheduling step observed in the provider.

---

### 6. SSLeay RAND_bytes replay

```bash
cd ssleay
python3 replay_rand_bytes_from_stir.py \
  sample01_rand_bytes/ssleay_stir_randbytes_trace.jsonl
```

Expected result:

```text
VALIDATION: PASS
```

The `ssleay/` module validates the OpenSSL 0.9.8 `ssleay_rand_bytes()`
post-stir output path. The replay starts from an anonymized
`state_after_stir` trace, selects the state window at index `240`,
recomputes each SHA-1 digest independently, verifies the XOR state update,
and reconstructs the final 32-byte `RAND_bytes` output.

The module also includes a workstation statistics decoder:

```bash
python3 decode_workstation_stats.py sample01_workstation/*.hex
```

Expected decoded values include identical `StatisticsStartTime` across
buffers captured within the same session, while
`PagingReadBytesRequested` exhibits small variations between samples.

In the provided dataset, buffers 1–3 were collected on a physical machine
and show consistent timestamps with minor paging fluctuations. Buffer 4 was
collected in a virtualized environment using a physical disk overlay,
resulting in a different timestamp and a lower `PagingReadBytesRequested`
value. This reflects a different capture environment rather than a decoding
inconsistency.

---

### 7. Wallet derivation

```bash
cd wallet
python3 wallet_proof.py sample01/prng_log_excerpt.jsonl
```

Expected:

```text
RAND==SECRET:   OK
WIF uncomp:     OK
P2PKH uncomp:   OK
```

This validates the deterministic derivation from the captured RAND_bytes
output to the corresponding Bitcoin private-key encoding and P2PKH address.

---

### Notes

* This repository is intentionally minimal and focuses on bit-exact reproducibility
* Large-scale campaigns and extended pool attribution are not included
* All observations correspond to Windows XP SP3
* The `randwin/` module provides structured decoding and inspection of captured
  Windows/OpenSSL entropy-source traces; it is not a statistical entropy estimator

Open component:

```text
seedbase_after → state20
```

---

### File Integrity

All binary and trace artifacts used in the experiments are provided with
reference SHA-256 hashes in the file:

```text
SHA256SUMS
```

These hashes allow byte-level verification of the inputs used in
the reproducibility scripts.

Verification command:

```bash
sha256sum -c SHA256SUMS
```

Note: hashes are provided for integrity and reproducibility purposes
only and do not imply cryptographic security guarantees.

---

### License

See LICENSE.

```
