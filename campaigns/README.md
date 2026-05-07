# Campaigns

This directory contains public replay artifacts derived from larger WinDbg/KD
instrumentation campaigns on Windows XP `CryptGenRandom`.

The full debugger campaign scripts are not necessarily included. Public
campaign artifacts are reduced to structured replay inputs, parser/replay
scripts, selected log excerpts, and explicit expected replay outputs.

## Included campaign

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

## Open component

The campaigns do not close the full provider-state transition:

```text
seedbase_after / persistent provider state → state20
```

That transition remains the main open component of the complete offline replay.
