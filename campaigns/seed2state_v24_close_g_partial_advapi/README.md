# seed2state_v24_close_g_partial_advapi

This campaign contains a cleaned replay/check artifact for the `seed2state_v24_close_g` experiment.

The original campaign name used `close_g` as an experimental target. The retained public artifact is deliberately described more narrowly: it validates local KSecDD/NewGenRandomEx/RC4/XOR transport relations and keeps the ADVAPI-side result classified as partial.

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
→ ADVAPI-side frame comparison
````

The retained samples are stored in:

```text
results_v24/samples/
```

## What this campaign verifies

The retained validator reports:

```text
V24_CLOSEG rc4_key_ksa PASS=16/16
V24_CLOSEG rc4_prga_xor PASS=16/16
V24_CLOSEG ksec_after_pre PASS=8/8
V24_CLOSEG advapi_frame_prefix PASS=8/8
OVERALL=PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX
```

The useful interpretation is:

```text
KSecDD RC4 key/KSA consistency     : validated
KSecDD RC4 PRGA/XOR relation       : validated
NewGenRandomEx after/pre stability : validated
ADVAPI-side relation               : partial, dump boundary needs fix
```

The retained validation material is:

```text
results_v24/v24_events.jsonl
results_v24/transport_xor_from_log_check.txt
results_v24/samples/
```

`results_v24/v24_events.jsonl` is a sanitized structured event index extracted from the original WinDbg log. Raw WinDbg command/output blocks are omitted from the public JSONL.

## What this campaign does not verify

This campaign does not close the full Windows XP `CryptGenRandom` provider function.

It does not prove:

```text
seedbase_after → provider persistent state → state20
```

It also does not claim full closure of the remaining provider-state function `G`.

The correct campaign status is:

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
  validate_v24_close_g_xor_from_log.py

results_v24/
  parse.stdout.txt
  samples/
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

The cleaned public artifact excludes raw logs, WinDbg collection scripts, setup wrappers, execution wrappers, Python cache files, and local temporary files.

## Reproduce checks

Run:

```bash
./run_tests.sh
```

Manual integrity check:

```bash
sha256sum -c SHA256SUMS
```

The retained output of the V24 XOR/transport check is available in:

```text
results_v24/transport_xor_from_log_check.txt
```

## Interpretation

This campaign strengthens the KSecDD/NewGenRandomEx/RC4/XOR part of the observed chain.

It should be cited as:

```text
V24 partial ADVAPI transport validation
```

not as:

```text
closure of G
```
