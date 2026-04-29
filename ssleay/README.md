# ssleay / OpenSSL 0.9.8 RAND replay

This directory contains small, self-contained replay tools for the
OpenSSL 0.9.8 `ssleay_rand_bytes()` path observed in the experiment.

## Contents

```text
decode_workstation_stats.py
  Decode 20-byte LanmanWorkstation statistic buffers observed during RAND_poll.

replay_rand_bytes_from_stir.py
  Recompute the 32-byte output of ssleay_rand_bytes from an anonymized trace.

sample01_workstation/
  Three 20-byte workstation statistic buffers.

sample01_rand_bytes/
  An anonymized trace containing:
  - state_after_stir
  - state_index_after_stir
  - state_num_after_stir
  - per-iteration SHA-1 inputs
  - per-iteration state XOR observations
  - final stage="after" RAND_bytes output
```

## Workstation statistics decoder

```bash
python3 decode_workstation_stats.py sample01_workstation/*.hex
```

Expected decoded values include identical StatisticsStartTime across
buffers captured within the same session, while
PagingReadBytesRequested exhibits small variations between samples.

In our dataset, buffers 1–3 were collected on a physical machine and show
consistent timestamps with minor paging fluctuations. Buffer 4 was
collected in a virtualized environment (disk overlay), resulting in a
different timestamp and a significantly lower
PagingReadBytesRequested value. This reflects reduced or abstracted I/O
activity in the VM rather than a decoding inconsistency.


## ssleay_rand_bytes replay

```bash
python3 replay_rand_bytes_from_stir.py \
  sample01_rand_bytes/ssleay_stir_randbytes_trace.jsonl \
  --index 240
```

Expected result:

```text
VALIDATION: PASS
```

The replay does not use the logged SHA-1 digests as inputs. For each
iteration, it:

1. extracts the state slice from `state_after_stir` at the selected index;
2. recomputes `SHA1(local_md || md_c || input_buf || state_slice)`;
3. verifies the logged digest;
4. independently recomputes the XOR update;
5. reconstructs emitted bytes from `digest[10:20]`;
6. compares the final 32-byte result with `stage="after"`.

Reviewer check:

```bash
python3 replay_rand_bytes_from_stir.py \
  sample01_rand_bytes/ssleay_stir_randbytes_trace.jsonl \
  --index 241
```

This must fail, because offset 241 selects a different state slice.
