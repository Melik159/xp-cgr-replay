# seed2state_v23_rc4_replay

This campaign contains a cleaned replay/check artifact for the `seed2state_v23_rc4_replay` experiment.

The purpose of the campaign is to validate the observed RC4/NewGenRandomEx transport segment in the Windows XP `KSecDD` path, using captured buffers and offline checks.

## Scope

This artifact focuses on the following observed segment:

```text
VLH checkpoint / seedbase_after
→ KSecDD!NewGenRandomEx
→ RC4 entry / first write / return
→ NewGenRandomEx after-gather / pre-return buffers
→ ADVAPI IOCTL after-c2 buffer
```

The campaign records repeated checkpoints around:

```text
KSecDD!NewGenRandomEx entry
VLH checkpoint
RC4 entry
RC4 first write
RC4 return
NewGenRandomEx after gather
NewGenRandomEx pre-return
ADVAPI IOCTL after C2
```

The retained samples are stored in:

```text
results_v23/samples/
```

## What this campaign verifies

This artifact verifies that the captured buffers around the KSecDD RC4/NewGenRandomEx path can be parsed and checked offline.

In particular, the campaign is intended to support:

```text
KSecDD NewGenRandomEx outbuf observations
RC4 state / outbuf checkpoints
first-write observations
NewGenRandomEx after-gather / pre-return consistency
ADVAPI IOCTL after-c2 transport comparison
```

The validation material is contained in:

```text
results_v23/v23_events.jsonl
results_v23/transport_check.txt
results_v23/VALIDATION.md
results_v23/samples/
```

## What this campaign does not verify

This campaign does not close the full CryptGenRandom provider function.

It does not claim to reconstruct:

```text
seedbase_after → provider persistent state → state20
```

It also does not replace the separate final-provider-block replay:

```text
(state20, aux20) → out40
```

The role of this campaign is narrower: it documents and checks the KSecDD RC4/NewGenRandomEx buffer path and its transport toward the ADVAPI-side IOCTL observation point.

## Directory layout

```text
parser/
  parse_seed2state_v23_rc4_replay.py

tools/
  validate_v23_transport.py

results_v23/
  parse.stdout.txt
  v23_events.jsonl
  transport_check.txt
  VALIDATION.md
  samples/

run_tests.sh
SHA256SUMS
```

The WinDbg collection scripts are intentionally not included in this cleaned public artifact. Only the replay/check material, captured sample buffers, parsed events, and validation summaries are retained.

## Reproduce checks

Run:

```bash
./run_tests.sh
```

This performs:

```text
Python syntax check
JSON / JSONL validation
presence check for required artifacts
optional transport validation tool invocation
SHA256 verification, if SHA256SUMS is present
```

Manual integrity check:

```bash
sha256sum -c SHA256SUMS
```

## Notes

The `.bin` files are captured sample buffers from the campaign. They are intentionally small and are retained because they are the input material for the offline checks.

The files under `results_v23/samples/` are ordered checkpoints from the retained run. Their names encode the observed event class and address anchor when available.
