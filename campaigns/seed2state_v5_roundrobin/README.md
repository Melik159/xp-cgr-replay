# Campaigns

This directory contains public replay artifacts derived from larger WinDbg/KD
instrumentation campaigns on Windows XP `CryptGenRandom`.

The full debugger campaign scripts are not included here. Public campaign
artifacts are reduced to structured replay inputs, parser/replay scripts,
selected log excerpts, and explicit expected replay outputs.

The purpose is reproducibility of the validated campaign result, not rerunning
the original WinDbg/KD instrumentation from scratch.

FF Included campaign

### seed2state_v5_roundrobin

This campaign validates the ADVAPI32 round-robin RC4 branch:

```text
KSecDD RC4_2 output
→ ADVAPI32 IOCTL buffer
→ ADVAPI32 eight-state RC4 manager
→ ADVAPI32 RC4 PRGA replay
→ SystemFunction036 output20
→ rsaenh aux20
```

It closes the downstream `G_aux` segment from captured ADVAPI32 RC4 state to
`aux20`.

## How to use the campaign artifact

From the repository root:

```bash
cd campaigns/seed2state_v5_roundrobin
```

Run the offline replay:

```bash
python3 parser/replay_seed2state_v5_roundrobin.py \
  results_v5/seed2state_v5_roundrobin_0e0c_2026-05-06_22-35-25-609.result.json \
  --dump-select
```

Expected final result:

```text
[RESULT] PASS
```

The full expected output is provided in:

```text
samples/replay_expected_output.txt
```

To compare the current replay with the retained expected output:

```bash
python3 parser/replay_seed2state_v5_roundrobin.py \
  results_v5/seed2state_v5_roundrobin_0e0c_2026-05-06_22-35-25-609.result.json \
  --dump-select \
  > /tmp/seed2state_v5_replay.txt

diff -u samples/replay_expected_output.txt /tmp/seed2state_v5_replay.txt
```

If there is no diff, the replay output matches the retained validation output.

## What to inspect

The most useful files are:

```text
seed2state_v5_roundrobin/README.md
    Detailed description of the artifact, validation scope, and residual gaps.

seed2state_v5_roundrobin/results_v5/*.result.json
    Structured parsed campaign result used by the replay script.

seed2state_v5_roundrobin/results_v5/*.info.txt
    Human-readable parser summary.

seed2state_v5_roundrobin/results_v5/summary.json
    Compact campaign summary.

seed2state_v5_roundrobin/samples/marker_index.txt
    Index of selected markers from the original WinDbg/KD log.

seed2state_v5_roundrobin/samples/log_excerpt_key_events.txt
    Selected log excerpts around key events.

seed2state_v5_roundrobin/samples/replay_expected_output.txt
    Expected replay output, including the final PASS verdict.
```

## What the replay validates

The replay validates the following relations:

```text
seedbase_after == LSA / KSecDD seed slot

KSecDD RC4_2 output[0x100]
==
ADVAPI32 IOCTL buffer[0x100]

ADVAPI32 manager selection follows a modulo-8 round-robin sequence

ADVAPI32 RC4 PRGA replay from captured state reproduces:
- generated output bytes
- post-PRGA RC4 state

ADVAPI32 RC4 PRGA output20
==
SystemFunction036 return buffer

SystemFunction036 output20
==
rsaenh aux20
```

## What is not included

This public artifact does not include:

```text
WinDbg/KD breakpoint body files
WinDbg/KD master setup scripts
the full raw debugger log
```

Only selected log excerpts and structured replay inputs are included.

## Open component

The campaign does not close the full provider-state transition:

```text
seedbase_after / persistent provider state → state20
```

That transition remains the main open component of the complete offline replay.
