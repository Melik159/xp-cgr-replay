# seed2state_v26_rsaenh_provider_only

This campaign validates the local RNG transition inside the Windows XP SP3
`rsaenh.dll` provider.

It is intentionally provider-local. It does not attempt to reconstruct the
upstream KSecDD, ADVAPI IOCTL, or `SystemFunction036` provenance of the provider
state.

## Purpose

The goal is to document and validate, from captured execution traces, how the
`rsaenh` provider consumes its local RNG state, produces output bytes, and
updates its provider state slot.

Validated local relation:

```text
state20 @ 68031958
+ aux20 local
→ rsaenh FIPS-style block @ 68027101
→ out40 local
→ out40[:len] copied to caller buffer
→ state20 updated through internal update helper
```

The campaign focuses on the provider mechanics after `rsaenh` has been reached.

## Scope

In scope:

```text
rsaenh provider RNG core
6800d640 provider function
68031958 state20 slot
68027101 FIPS-style block entry
680271D5 update-A return site
68027297 update-B return site
out40 local buffer
out40[:len] → caller destination buffer
self-test vector consistency
```

Out of scope:

```text
KSecDD / VeryLargeHashUpdate
ADVAPI IOCTL transport
SystemFunction036 → aux20 provenance
seedbase_after → provider state provenance
full upstream G closure
```

## What the campaign shows

The captured trace demonstrates two provider behaviors.

First, the provider self-test path:

```text
6802F8B8 static seed
→ local stack source
→ 68031958 state20 slot
→ provider update
→ comparison with expected vector at 6802F8CC
```

Second, runtime provider calls:

```text
6800d640 runtime call
source argument = NULL
state20 is consumed from 68031958
aux20 is passed as local FIPS input
out40 is produced locally
out40[:len] is copied to the caller buffer
68031958 is updated by the provider update helper
```

The key validated property for each captured output copy is:

```text
destination[:len] == out40[:len]
```

## Public sample

The reduced public sample is in:

```text
samples/sample01/
```

It contains extracted binary samples and validation reports, not the full raw KD
log.

Relevant files:

```text
samples/sample01/manifest.json
samples/sample01/manifest.tsv
samples/sample01/blobs/*.bin
samples/sample01/v26_provider_validation.txt
samples/sample01/v26_replay_samples.txt
```

The `manifest.json` and `manifest.tsv` map extracted binary blobs back to their
trace markers, addresses, source line ranges, and semantic class.

## Parse the reduced trace excerpt

The parser validates the marker-level trace evidence and prints a human-readable
report.

```bash
python3 parser/parse_v26_rsaenh_provider_only.py \
  samples/sample01/log_excerpt_key_events.txt
```

Expected result:

```text
selftest_stack_source_equals_6802F8CC  PASS
fips_entry_count                       PASS
fips_update_A_seen                     PASS
fips_update_B_seen                     PASS
out_copy_prefix_summary                PASS
OVERALL                                PASS
```

## Replay from extracted samples

The replay script validates the public binary samples without requiring the raw
KD log.

```bash
python3 tools/replay_v26_samples.py samples/sample01
```

Expected result:

```text
copy#1 len=32 status=PASS
copy#2 len=40 status=PASS
copy#3 len=40 status=PASS
copy#4 len=10 status=PASS
copy#5 len=32 status=PASS
copy#6 len=32 status=PASS
summary PASS=6/6
```

This replay checks that each captured caller destination buffer equals the
corresponding `out40` prefix for the effective copied length.

## Evidence model

The campaign separates three layers of evidence.

### 1. Self-test consistency

The static seed and expected state vectors are extracted from the provider:

```text
6802F8B8 static seed
6802F8CC expected post-update state
```

The parser checks that the local stack source after the provider update equals
the expected vector.

### 2. FIPS-style provider transition

For each captured provider block, the trace records:

```text
state20_after
out40
aux20
update-A marker
update-B marker
```

This confirms that the provider enters the FIPS-style block and reaches both
state-update return sites.

### 3. Output-copy validation

For each captured copy, the campaign extracts:

```text
out40 local
destination buffer after copy
effective copy length
```

The replay validates:

```text
destination[:len] == out40[:len]
```

## Result

For `sample01`:

```text
provider self-test vector      PASS
FIPS entries observed          PASS
FIPS update-A observed         PASS
FIPS update-B observed         PASS
output-copy replay             PASS 6/6
overall                        PASS
```

## Scientific status

This campaign supports the following narrow statement:

```text
For the captured executions, the local rsaenh provider transition is validated:
state20 at 68031958 is consumed by the provider FIPS-style block together with
local aux20, out40 is produced, out40[:len] is copied to the caller buffer, and
the provider state slot is updated.
```

It does not claim that the upstream provenance of `state20` has been reconstructed.

In the global chain, V26 should therefore be classified as:

```text
rsaenh provider local transition: validated
upstream KSecDD/ADVAPI → state20 provenance: out of scope
```
