# seed2state_v18_1_ksecdd_kernel_outbuf_manual

## Summary

This campaign validates a manually captured KSecDD-to-ADVAPI boundary in the Windows XP SP3 `SystemFunction036` / `CryptGenRandom` path.

The retained sample shows that a captured KSecDD kernel-side `0x100`-byte output buffer is recovered byte-for-byte as the first ADVAPI IOCTL `0x390008` output buffer. The campaign then continues the already validated ADVAPI-side path from IOCTL outbuf to RC4 KSA state, useful PRGA replay, and `SystemFunction036` output.

Validated local chain:

```text
KSecDD kernel_outbuf[0x100]
→ ADVAPI IOCTL 0x390008 outbuf[0x100]
→ RC4 KSA from outbuf[0:256]
→ ADVAPI RC4 state_before
→ RC4 PRGA XOR-in-place
→ SystemFunction036 output20
```

## Retained checks

```text
ksec_kernel_to_ioctl_exact_matches=1
ioctl_to_rc4_ksa_matches=10
useful_prga_replay_ok=4/4
```

## Main evidence

The key boundary match is:

```text
KSEC#1 kernel_outbuf=8a0b15f8 len=00000100 dump_len=256
IOCTL#1 outbuf=0023f484 outlen=00000100 dump_len=256
MATCH exact KSEC#1 == IOCTL#1
```

First 16 bytes of the matched buffer:

```text
c4aa4adab1fbd332386919a8daaddbcd
```

This establishes, for the retained sample:

```text
KSecDD kernel_outbuf[0x100]
==
ADVAPI IOCTL#1 outbuf[0x100]
```

## ADVAPI continuation

The same artifact also validates the downstream ADVAPI RC4 segment:

```text
ADVAPI IOCTL outbuf[0x100]
→ RC4 KSA
→ ADVAPI RC4 state
→ useful PRGA20 replay
→ SystemFunction036 output20
```

Observed KSA matches:

```text
MATCH ioctl_01 -> prga_001 i=00 j=00
MATCH ioctl_02 -> prga_002 i=00 j=00
MATCH ioctl_03 -> prga_003 i=00 j=00
MATCH ioctl_04 -> prga_004 i=00 j=00
MATCH ioctl_05 -> prga_005 i=00 j=00
MATCH ioctl_06 -> prga_006 i=00 j=00
MATCH ioctl_07 -> prga_007 i=00 j=00
MATCH ioctl_08 -> prga_008 i=00 j=00
MATCH ioctl_02 -> prga_010 i=00 j=00
MATCH ioctl_03 -> prga_011 i=00 j=00
```

Useful PRGA replay:

```text
prga_001: output_match=True state_match=True
prga_009: output_match=True state_match=True
prga_010: output_match=True state_match=True
prga_011: output_match=True state_match=True
[SUMMARY] useful_prga_replay_ok=4/4
```

## Reproduction

From the root of this artifact:

```bash
./reproduce_sample01.sh
```

Equivalent manual commands:

```bash
python3 scripts/check_ksec_kernel_to_advapi_ioctl.py samples/sample01/raw

python3 scripts/check_ioctl_to_rc4_ksa.py samples/sample01/raw

python3 scripts/replay_prga_useful_only.py samples/sample01/raw
```

Expected markers:

```text
ksec_kernel_to_ioctl_exact_matches=1
ioctl_to_rc4_ksa_matches=10
useful_prga_replay_ok=4/4
```

## Directory layout

```text
README.md
SHA256SUMS
reproduce_sample01.sh

logs/
  sample01.REDACTED.log

reports/
  sample01.events.jsonl
  sample01.ksec_ioctl.txt
  sample01.ksec_ioctl.csv
  sample01.ioctl_ksa.txt
  sample01.ioctl_ksa.csv
  sample01.prga_replay.txt
  sample01.report.txt

samples/
  sample01/
    README.md
    raw/
      ksec_01/
      ioctl_01/ ... ioctl_08/
      prga_001/ ... prga_011/
      ksec_ioctl_matches.json
      ioctl_ksa_matches.json

scripts/
  check_ksec_kernel_to_advapi_ioctl.py
  check_ioctl_to_rc4_ksa.py
  replay_prga_useful_only.py
  parse_seed2state_v18_1.py
```

## Scope

This artifact validates the local bridge:

```text
captured KSecDD kernel_outbuf[0x100]
→ matching ADVAPI IOCTL outbuf[0x100]
→ RC4 KSA states
→ useful PRGA replay
→ SystemFunction036 output20
```

It does not reconstruct:

```text
VLH seedbase_after
→ KSecDD kernel_outbuf[0x100]
```

It also does not reconstruct:

```text
seedbase_after / persistent provider state
→ state20
```

## Not claimed

This artifact does not claim:

```text
complete Windows XP CryptGenRandom reconstruction
complete seedbase_after → provider_state → state20 replay
complete entropy assessment
practical attack against Bitcoin or historical keys
```

## Interpretation

This campaign strengthens the previous ADVAPI-side validation by adding a manually captured kernel-side boundary:

```text
KSecDD kernel_outbuf[0x100] == ADVAPI IOCTL#1 outbuf[0x100]
```

The result is a narrower but stronger boundary statement: the first ADVAPI IOCTL output buffer used downstream by the RC4/KSA/PRGA path is byte-identical to the captured KSecDD kernel output buffer in the retained sample.

The remaining upstream question is the derivation of that KSecDD kernel output buffer from `seedbase_after` and prior kernel/provider state.
