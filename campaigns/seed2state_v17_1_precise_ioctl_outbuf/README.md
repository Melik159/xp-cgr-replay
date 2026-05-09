# seed2state_v17_1_precise_ioctl_outbuf

This artifact documents a precise ADVAPI IOCTL-output-buffer to RC4-state campaign for the Windows XP SP3 `SystemFunction036` path.

## Purpose

The campaign validates the following local chain:

```text
ADVAPI IOCTL 0x390008 outbuf[0x100]
→ ADVAPI RC4 KSA
→ ADVAPI RC4 state
→ useful PRGA20 calls
→ SystemFunction036 output20
```

The campaign does not claim to close the full Windows XP `CryptGenRandom` provider-state derivation. Its scope is the precise ADVAPI-side IOCTL outbuf to RC4-state / PRGA segment.

## Main result

The retained sample is `sample01`.

Observed parser summary:

```text
IOCTL outbufs captured : 8
PRGA calls observed    : 11
Useful PRGA replays    : 4/4
Direct KSA matches     : 10
```

Useful PRGA replay:

```text
prga_001: output_match=True state_match=True
prga_009: output_match=True state_match=True
prga_010: output_match=True state_match=True
prga_011: output_match=True state_match=True
[SUMMARY] useful_replay_ok=4/4
```

KSA scan:

```text
MATCH state=prga_001 outbuf=ioctl_01/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_002 outbuf=ioctl_02/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_003 outbuf=ioctl_03/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_004 outbuf=ioctl_04/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_005 outbuf=ioctl_05/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_006 outbuf=ioctl_06/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_007 outbuf=ioctl_07/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_008 outbuf=ioctl_08/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_010 outbuf=ioctl_02/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00
MATCH state=prga_011 outbuf=ioctl_03/V17_1_IOCTL_OUTBUF_100.bin off=0 len=256 i=00 j=00

[SUMMARY]
direct_ksa_matches=10
```

## Independent negative-control audit

The artifact also includes an independent audit script:

```text
tools/audit_sample01_negative_controls.py
```

This script checks the extracted binary samples directly, not only the parser report.

It verifies:

```text
8 IOCTL outbufs present
11 PRGA directories present
all IOCTL outbufs are exactly 256 bytes
all 8 IOCTL outbufs are distinct
KSA(outbuf_i) == corresponding PRGA state_before_sij[:256]
mutated outbuf_i rejects the KSA match
useful PRGA replay matches output and post-PRGA state
mutated PRGA state rejects the replay
```

Expected result:

```text
[AUDIT RESULT] PASS
```

This reduces the risk of a parser-confirmation artifact or accidental scan match.

## Directory layout

```text
README.md
reproduce_sample01.sh
SHA256SUMS

parser/
  parse_seed2state_v17_1_precise.py

tools/
  replay_prga_useful_only.py
  scan_ioctl_outbuf_to_rc4_ksa.py
  audit_sample01_negative_controls.py

sample01/
  raw/
    sample01.log

  results/
    sample01.report.txt
    sample01.states.jsonl
    sample01.ksa_scan.txt
    sample01.ksa_scan.csv

  samples/
    ioctl_*/
    prga_*/
    samples.jsonl
```

## Reproduction

From the root of this artifact:

```bash
./reproduce_sample01.sh
```

Equivalent manual commands:

```bash
BASE="sample01"

python3 parser/parse_seed2state_v17_1_precise.py \
  "sample01/raw/${BASE}.log" \
  --pretty \
  --jsonl "sample01/results/${BASE}.states.jsonl" \
  --samples "sample01/samples" \
  | tee "sample01/results/${BASE}.report.txt"

python3 tools/replay_prga_useful_only.py \
  sample01/samples

python3 tools/scan_ioctl_outbuf_to_rc4_ksa.py \
  sample01/samples \
  --csv "sample01/results/${BASE}.ksa_scan.csv" \
  | tee "sample01/results/${BASE}.ksa_scan.txt"

python3 tools/audit_sample01_negative_controls.py
```

Expected reproduction markers:

```text
[SUMMARY] useful_replay_ok=4/4
direct_ksa_matches=10
[AUDIT RESULT] PASS
```

## Interpretation

This campaign validates the ADVAPI-side local mapping:

```text
IOCTL outbuf[0x100]
→ RC4 KSA
→ ADVAPI RC4 state
→ PRGA20
→ SystemFunction036 output20
```

It also shows the ADVAPI eight-state behavior: the first eight IOCTL buffers initialize the corresponding RC4 states, and later useful PRGA calls reuse already initialized states.

The residual gap is outside the scope of this artifact:

```text
KSecDD / provider upstream state
→ IOCTL outbuf[0x100]
```

and, separately:

```text
rsaenh persistent provider state
→ state20
```

## Scope

This artifact should be interpreted narrowly.

Closed or locally validated:

```text
captured IOCTL outbuf[0x100]
→ RC4 KSA
→ ADVAPI RC4 state
→ useful PRGA replay
→ SystemFunction036 output20
```

Not claimed here:

```text
complete Windows XP CryptGenRandom reconstruction
complete seedbase_after → provider_state → state20 replay
complete entropy assessment
practical attack against Bitcoin or historical keys
```

## Summary

The retained `sample01` provides a reproducible validation of the ADVAPI-side IOCTL-output-buffer to RC4-state segment.

The strongest empirical results are:

```text
useful PRGA replay : 4/4
direct KSA matches : 10
IOCTL outbufs      : 8
negative controls  : PASS
```

This reduces the previously opaque ADVAPI part of the chain and isolates the remaining unresolved parts to upstream provider/KSecDD state derivation and the separate rsaenh persistent-state mapping to `state20`.
