# XP CryptGenRandom Component-Level Replay

This repository provides reproducibility artifacts for the paper:

**An Empirical Analysis of CryptGenRandom in Windows XP SP3 and Its Historical Relevance to Bitcoin 0.1.5**

The repository contains executable validation scripts and cleaned campaign artifacts for experimentally isolated components of the observed Windows XP SP3 `CryptGenRandom` pipeline.

The goal is reproducibility of specific observed/replayed relations, not a claim of complete end-to-end reconstruction.

---

## Scope

The repository supports independent verification of selected relations observed in the Windows XP SP3 `CryptGenRandom` path.

Validated or replayed components include:

### Kernel entropy processing

```text
pool → VeryLargeHashUpdate / VLH → seedbase_after
````

### Provider-side final block

```text
(state20, aux20) → out40 → CryptGenRandom output[0:32]
```

### Internal primitives

* SHA-1 compression used in the final FIPS-style provider block
* RC4 key-scheduling algorithm, KSA
* RC4 PRGA / XOR relations in selected KSecDD and ADVAPI-side campaigns
* Local provider XOR relations where captured inputs are available

### Open component

The main remaining open component is still:

```text
seedbase_after / provider persistent state → state20
```

This repository does **not** claim a complete replay of:

```text
seedbase_after → provider_state → state20 → out40 → CryptGenRandom output
```

It also does **not** claim:

```text
complete Windows XP CryptGenRandom reconstruction
complete entropy assessment
practical attack against Bitcoin or historical keys
```

---

## Repository Structure

Core replay modules:

* `vlh/` — kernel-side `VeryLargeHashUpdate` replay: `pool → seedbase_after`
* `provider/` — provider local mixing and output-construction checks
* `fips/` — SHA-1 compression replay for the final provider block
* `rc4/` — RC4 KSA validation
* `ssleay/` — OpenSSL 0.9.8 post-stir `ssleay_rand_bytes()` replay
* `wallet/` — wallet-level consistency check from observed `RAND_bytes` output to WIF/P2PKH material
* `campaigns/` — cleaned campaign artifacts derived from larger WinDbg/KD trace campaigns

---

## Reproducibility

All scripts operate on captured binary artifacts and reproduce outputs at byte level where the corresponding relation is claimed as replayed.

### 1. VLH kernel phase

```bash
cd vlh
python3 validate_vlh_campaign.py
```

Expected result:

```text
MAPPING_PASS: True
SEED_PASS: True
PASS: True
```

This validates:

```text
pool segmentation
SHA-1-based VLH construction
exact reconstruction of seedbase_after
```

---

### 2. Provider XOR and FIPS-style construction

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

### 3. FIPS block / SHA-1 compression

```bash
cd fips
python3 replay_fips186_block.py \
  sample01/p1_block64.bin \
  sample01/p2_block64.bin \
  --out40-after sample01/out40_after.bin
```

Expected result:

```text
std_match : True
```

This confirms that the final block is reproduced using standard SHA-1 compression.

---

### 4. RC4 KSA

```bash
cd rc4
python3 validate_ksa.py
```

Expected result:

```text
match: OK
BIT_EXACT_MATCH: 2048 bits
```

This validates the RC4 key-scheduling step observed in the provider.

---

### 5. OpenSSL post-stir replay

The `ssleay/` module validates the OpenSSL 0.9.8 `ssleay_rand_bytes()` post-stir output path.

The replay starts from an anonymized `state_after_stir` trace, selects the state window at index `240`, recomputes each SHA-1 digest independently, verifies the XOR state update, and reconstructs the final 32-byte `RAND_bytes` output.

This does not reconstruct the full OpenSSL stirring process from Windows inputs. It validates the post-stir byte-generation boundary.

---

### 6. Wallet derivation

```bash
cd wallet
python3 wallet_proof.py sample01/prng_log_excerpt.jsonl
```

Expected result:

```text
RAND==SECRET:   OK
WIF uncomp:     OK
P2PKH uncomp:   OK
```

This validates the deterministic derivation from the captured `RAND_bytes` output to the corresponding Bitcoin private-key encoding and P2PKH address.

This is a wallet-level consistency check. It is not evidence about the internal Windows RNG or the OpenSSL stirring phase.

---

## Campaigns

The `campaigns/` directory contains public replay/check artifacts derived from larger WinDbg/KD trace campaigns.

Each campaign is intentionally narrow: it validates one experimentally isolated relation and should not be read as a complete replay of Windows XP `CryptGenRandom`.

Cleaned campaign artifacts generally contain:

```text
README.md
samples or results directory
parser/check scripts
validation summaries
run_tests.sh
SHA256SUMS
```

Raw WinDbg logs, local temporary files, Python caches, duplicate setup wrappers, and WinDbg collection scaffolding are generally excluded from cleaned public artifacts unless explicitly required.

---

## Current Included Campaigns

### `seed2state_v5_roundrobin/`

Validates the downstream KSecDD/ADVAPI/SystemFunction036/rsaenh `aux20` path.

It observes the KSecDD `RC4_2` 0x100-byte output as an ADVAPI-side IOCTL buffer, validates the ADVAPI32 eight-state RC4 round-robin manager, replays non-zero ADVAPI32 RC4 PRGA calls from captured states, correlates PRGA output with `SystemFunction036`, and correlates `SystemFunction036` output with `rsaenh aux20`.

Validated relation:

```text
KSecDD RC4_2 output
→ ADVAPI32 IOCTL buffer
→ ADVAPI32 eight-state RC4 manager
→ ADVAPI32 RC4 PRGA
→ SystemFunction036 output20
→ rsaenh aux20
```

---

### `seed2state_v17_1_precise_ioctl_outbuf/`

Provides a tighter ADVAPI-side validation of the IOCTL-output-buffer to RC4-state segment.

It starts from captured ADVAPI IOCTL `0x390008` `outbuf[0x100]` samples, verifies that `outbuf[0:256]` reproduces the corresponding RC4 KSA states, replays useful PRGA20 calls from captured states, checks the post-PRGA state evolution, and includes negative controls on mutated IOCTL buffers and mutated PRGA states.

Validated relation:

```text
captured ADVAPI IOCTL 0x390008 outbuf[0x100]
→ RC4 KSA from outbuf[0:256]
→ ADVAPI RC4 state
→ useful PRGA20 replay
→ SystemFunction036 output20
```

Negative controls:

```text
mutated IOCTL outbuf → KSA match rejected
mutated PRGA state   → PRGA replay rejected
```

---

### `seed2state_v18_1_ksecdd_kernel_outbuf_manual/`

Validates a manually captured KSecDD-to-ADVAPI boundary.

It shows that a captured KSecDD kernel-side `kernel_outbuf[0x100]` is byte-identical to the first ADVAPI IOCTL `0x390008` `outbuf[0x100]`, then continues the replay through ADVAPI RC4 KSA states, useful PRGA20 calls, and `SystemFunction036 output20`.

Validated relation:

```text
captured KSecDD kernel_outbuf[0x100]
→ matching ADVAPI IOCTL 0x390008 outbuf[0x100]
→ RC4 KSA from outbuf[0:256]
→ ADVAPI RC4 state
→ useful PRGA20 replay
→ SystemFunction036 output20
```

The local kernel/user boundary check is:

```text
KSecDD kernel_outbuf[0x100] == ADVAPI IOCTL#1 outbuf[0x100]
```

---

### `seed2state_v19c_fips_state20_update_replay/`

Provides provider-side replay/check material around captured `state20_before`, `aux20`, `out40_after`, and `state20_after` values.

This campaign validates a local final-provider-state update boundary from captured inputs.

Validated local boundary:

```text
state20_before
aux20
→ provider final generation/update block
→ out40_after
→ state20_after
```

It does not reconstruct the upstream provider persistent-state derivation of `state20`.

It does not close:

```text
seedbase_after → provider persistent state → state20
```

---

### `seed2state_v20_1_precise_newgenrandomex_outbuf/`

Provides a precise KSecDD/ADVAPI transport artifact.

It checks the relation between KSecDD `NewGenRandomEx` output-buffer observations and ADVAPI-side IOCTL buffers.

Observed local boundary:

```text
VLH seedbase_after checkpoint
→ KSecDD!NewGenRandomEx entry
→ KSecDD!NewGenRandomEx after-gather / pre-return outbuf
→ ADVAPI IOCTL after-c2 buffer
```

This campaign does not validate the final provider block and does not close the provider-state transition to `state20`.

---

### `seed2state_v22_writer_probe/`

Documents first-write observations around the KSecDD `NewGenRandomEx` output buffer.

It checks consistency between writer checkpoints and retained KSecDD/ADVAPI transport samples.

Observed boundary:

```text
VLH checkpoint / seedbase_after
→ KSecDD!NewGenRandomEx
→ output-buffer first-write observation
→ NewGenRandomEx after-gather / pre-return buffers
→ ADVAPI IOCTL after-c2 buffer
```

This campaign is useful for localizing where the KSecDD output buffer begins to be written. It does not reconstruct the full provider-state function.

---

### `seed2state_v23_rc4_replay/`

Retains RC4/NewGenRandomEx checkpoints and transport validation material.

It contains ordered checkpoints around VLH, `NewGenRandomEx`, RC4 entry/return, first-write observations, pre-return buffers, and ADVAPI IOCTL after-c2 observations.

Observed/replayed segment:

```text
VLH checkpoint / seedbase_after
→ KSecDD!NewGenRandomEx
→ RC4 entry / first write / return
→ NewGenRandomEx after-gather / pre-return buffers
→ ADVAPI IOCTL after-c2 buffer
```

This campaign validates the KSecDD RC4/NewGenRandomEx buffer path and its transport toward the ADVAPI-side IOCTL observation point.

It does not close:

```text
seedbase_after → provider persistent state → state20
```

---

### `seed2state_v24_close_g_partial_advapi/`

This campaign is a cleaned public artifact derived from the V24 `close_g` experiment.

The name is deliberately conservative: it is a partial ADVAPI transport validation, not a complete closure of the remaining provider-state function `G`.

Retained validator result:

```text
V24_CLOSEG rc4_key_ksa PASS=16/16
V24_CLOSEG rc4_prga_xor PASS=16/16
V24_CLOSEG ksec_after_pre PASS=8/8
V24_CLOSEG advapi_frame_prefix PASS=8/8
OVERALL=PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX
```

Validated local relations:

```text
KSecDD RC4 key/KSA consistency     : validated
KSecDD RC4 PRGA/XOR relation       : validated
NewGenRandomEx after/pre stability : validated
ADVAPI-side relation               : partially validated; ADVAPI capture window still needs refinement.
```

This campaign strengthens the KSecDD/NewGenRandomEx/RC4/XOR segment, but it does not claim full closure of `G`.

It does not prove:

```text
seedbase_after → provider persistent state → state20
```

Correct status:

```text
PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX
```

not:

```text
FULL_CLOSE_G
```

### `seed2state_v26_rsaenh_provider_only`

Provider-local validation campaign for the Windows XP SP3 `rsaenh.dll` RNG path.

This campaign validates the local provider transition observed in captured executions:

```text
state20 @ 68031958
+ local aux20
→ rsaenh FIPS-style block @ 68027101
→ out40
→ out40[:len] copied to caller buffer
→ provider state slot updated

```

Included artifacts:


```
campaigns/seed2state_v26_rsaenh_provider_only/
├── parser/                         parser for the reduced trace excerpt
├── samples/sample01/blobs/          extracted binary samples
├── samples/sample01/manifest.json   sample manifest
├── samples/sample01/manifest.tsv    tabular manifest
├── samples/sample01/v26_provider_validation.txt
└── tools/replay_v26_samples.py      replay check from extracted samples

```

Main result for sample01:


```
selftest_stack_source_equals_6802F8CC  PASS
fips_entry_count                       PASS
fips_update_A_seen                     PASS
fips_update_B_seen                     PASS
out_copy_prefix_summary                PASS 6/6
OVERALL                                PASS

```
Scope note: this campaign is intentionally rsaenh provider-local. It does not claim to reconstruct the upstream KSecDD/ADVAPI/SystemFunction036 provenance of state20.

---

## Campaign Status Summary

The V5, V17.1, and V18.1 campaigns validate the downstream `G_aux` / ADVAPI-to-`aux20` branch from captured ADVAPI RC4 material to `SystemFunction036 output20` and, in the V5 campaign, to `rsaenh aux20`.

V18.1 additionally validates the local boundary from a captured KSecDD kernel output buffer to the corresponding ADVAPI IOCTL output buffer.

V19c validates a local provider-side state/update boundary around captured `state20`, `aux20`, and `out40` material.

V20.1, V22, V23, and V24 progressively refine the KSecDD `NewGenRandomEx`, RC4, writer, XOR, and ADVAPI transport observations.

Together, these campaigns improve the experimental decomposition of the path, but they do not close:

```text
VLH seedbase_after → KSecDD kernel_outbuf[0x100]
seedbase_after / persistent provider state → state20
```

They also do not claim:

```text
complete Windows XP CryptGenRandom reconstruction
complete seedbase_after → provider_state → state20 replay
complete entropy assessment
practical attack against Bitcoin or historical keys
```

---

## File Integrity

Binary artifacts and retained text artifacts are provided with reference SHA-256 hashes in the relevant `SHA256SUMS` files.

Typical verification command:

```bash
sha256sum -c SHA256SUMS
```

Some campaign directories contain their own `SHA256SUMS` file. Verify them from inside the corresponding directory:

```bash
cd campaigns/<campaign_name>
sha256sum -c SHA256SUMS
```

Hashes are provided for integrity and reproducibility purposes only and do not imply cryptographic security guarantees.

---

## Notes

* This repository is intentionally focused on bit-exact reproducibility and trace-grounded validation.
* Cleaned public campaign artifacts omit raw/private/local debugging material where possible.
* All observations correspond to the studied Windows XP SP3 environment and should not be generalized automatically to other Windows versions, service packs, providers, or binary layouts.
* The main remaining open component is still:

```text
seedbase_after / persistent provider state → state20
```

---

## License

See `LICENSE`.

```
```
