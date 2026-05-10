# seed2state_v20_1_precise_newgenrandomex_outbuf

This campaign validates the precise boundary between `KSecDD!NewGenRandomEx`
and the ADVAPI-side IOCTL output buffer.

For the captured sequence, each 0x100-byte buffer observed in KSecDD:

```text
KSecDD!NewGenRandomEx outbuf[0x100] after GatherRandomKey
KSecDD!NewGenRandomEx outbuf[0x100] before return
```

is reproduced byte-for-byte as the ADVAPI-side IOCTL output buffer.

## Result

```text
[V20.1 KSECDD NEWGENRANDOMEX OUTBUF -> ADVAPI IOCTL CHECK]
ksec_outbufs=16
advapi_ioctl_outbufs=8

[SUMMARY] exact_matches=16
```

The 16 matches correspond to:

```text
8 after-GatherRandomKey KSecDD outbufs  -> ADVAPI IOCTL outbufs
8 pre-return KSecDD outbufs             -> ADVAPI IOCTL outbufs
```

## What is validated

This campaign closes the transport boundary:

```text
KSecDD!NewGenRandomEx outbuf[0x100]
→ ADVAPI IOCTL outbuf[0x100]
```

The same 0x100-byte buffers are observed:

1. inside KSecDD after `GatherRandomKey`;
2. inside KSecDD immediately before `NewGenRandomEx` returns;
3. on the ADVAPI side as the IOCTL output buffer.

## Reproduce

Parse the WinDbg log:

```bash
python3 scripts/parse_seed2state_v20_1.py \
  logs/sample01.REDACTED.log \
  --samples samples/sample01_reparsed \
  --jsonl reports/sample01.reparsed.events.jsonl \
  --pretty
```

Check the KSecDD-to-ADVAPI equality:

```bash
python3 scripts/check_ksec_newgen_to_advapi_ioctl.py \
  samples/sample01 \
  --csv reports/sample01.recheck.ksec_advapi.csv
```

Expected checker summary:

```text
[V20.1 KSECDD NEWGENRANDOMEX OUTBUF -> ADVAPI IOCTL CHECK]
ksec_outbufs=16
advapi_ioctl_outbufs=8

[SUMMARY] exact_matches=16
```

## Directory layout

```text
logs/
  sample01.REDACTED.log

reports/
  sample01.events.jsonl
  sample01.report.txt
  sample01.ksec_advapi.csv
  sample01.ksec_advapi.txt

samples/
  sample01/
    vlh_01..vlh_08/
    ksec_entry_01..ksec_entry_07/
    ksec_after_gather_01..ksec_after_gather_08/
    ksec_pre_return_01..ksec_pre_return_08/
    advapi_ioctl_01..advapi_ioctl_16/

scripts/
  parse_seed2state_v20_1.py
  check_ksec_newgen_to_advapi_ioctl.py

```

## Scope

This campaign validates:

```text
KSecDD NewGenRandomEx outbuf[0x100]
→ ADVAPI IOCTL outbuf[0x100]
```

It does not by itself close the upstream derivation:

```text
VLH seedbase_after
→ KSecDD NewGenRandomEx outbuf[0x100]
```

That remains a separate upstream modelling/replay target.
