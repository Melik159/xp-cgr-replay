# seed2state_v24_close_g_partial_advapi

This campaign contains a cleaned replay/check artifact for the `seed2state_v24_close_g` experiment.

The original campaign name used "close_g" as an experimental target. The retained public artifact is deliberately named and described more narrowly: this is a partial ADVAPI transport validation, not a complete closure of the remaining provider-state function `G`.

The observed validator result is:

```text
V24_CLOSEG rc4_key_ksa PASS=16/16
V24_CLOSEG rc4_prga_xor PASS=16/16
V24_CLOSEG ksec_after_pre PASS=8/8
V24_CLOSEG advapi_frame_prefix PASS=8/8
OVERALL=PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX
```

## Scope

This artifact focuses on the KSecDD/NewGenRandomEx/RC4/ADVAPI transport segment.

The retained evidence covers repeated cycles around:

```text
VLH checkpoint / seedbase_after
→ KSecDD!NewGenRandomEx
→ RC4 key / KSA material
→ RC4 PRGA / XOR observations
→ NewGenRandomEx after-gather buffer
→ NewGenRandomEx pre-return buffer
→ ADVAPI IOCTL frame prefix comparison
```

The retained samples are stored in:

```text
results_v24/samples/
```

## What this campaign verifies

This campaign validates several local transport and RC4 relations from the retained V24 run.

The checker output reports:

```text
rc4_key_ksa     PASS=16/16
rc4_prga_xor    PASS=16/16
ksec_after_pre  PASS=8/8
advapi_prefix   PASS=8/8, prefix 144/256 bytes
```

The useful interpretation is:

```text
KSecDD RC4 key/KSA consistency       : validated
KSecDD RC4 PRGA/XOR relation         : validated
NewGenRandomEx after/pre stability   : validated
ADVAPI-side relation                 : partially validated, 144/256-byte prefix
```

The retained reports are:

```text
results_v24/v24_events.jsonl
results_v24/transport_check.txt
results_v24/transport_xor_from_log_check.txt
```

## What this campaign does not verify

This campaign does not close the full Windows XP `CryptGenRandom` provider function.

It does not prove:

```text
seedbase_after → provider persistent state → state20
```

It also does not fully prove:

```text
KSecDD final outbuf[0x100] == ADVAPI IOCTL outbuf[0x100]
```

because the retained V24 ADVAPI-side comparison validates only a prefix:

```text
144 / 256 bytes
```

The correct status is therefore:

```text
PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX
```

not:

```text
FULL_CLOSE_G
```

## Directory layout

```text
parser/
  parse_seed2state_v24_close_g.py

tools/
  validate_v24_close_g.py
  validate_v24_close_g_xor_from_log.py

results_v24/
  parse.stdout.txt
  samples/
  transport_check.txt
  transport_xor_from_log_check.txt
  v24_events.jsonl

sanity_v24/
  errors_and_stops.txt
  log.lines.txt
  log.sha256
  log.size.txt
  marker_counts.txt
  timeline_core.txt

run_tests.sh
SHA256SUMS
```

The raw WinDbg log and WinDbg collection scaffolding are intentionally not included in this cleaned public artifact.

The cleaned public artifact excludes the raw log, WinDbg collection scaffolding, setup wrappers, execution wrappers, Python cache files, and local temporary files.

## Reproduce checks

Run:

```bash
./run_tests.sh
```

Manual integrity check:

```bash
sha256sum -c SHA256SUMS
```

The `validate_v24_close_g_xor_from_log.py` tool is retained for transparency, but its original full mode requires the raw WinDbg log, which is not distributed in this cleaned artifact. The retained output of that check is available in:

```text
results_v24/transport_xor_from_log_check.txt
```

## Interpretation

This campaign is useful because it strengthens the KSecDD/NewGenRandomEx/RC4/XOR part of the chain.

It should be cited as:

```text
V24 partial ADVAPI transport validation
```

not as:

```text
closure of G
```

The remaining required fix is the ADVAPI dump boundary. A later campaign should aim for:

```text
ADVAPI 256/256 exact outbuf match
```

instead of the current:

```text
ADVAPI prefix 144/256 match
```
