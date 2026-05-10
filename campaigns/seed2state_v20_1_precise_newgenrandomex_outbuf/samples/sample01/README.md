# sample01

This directory contains the extracted samples for V20.1.

The important equality is:

```text
ksec_after_gather_N/outbuf_100.bin == advapi_ioctl_M/outbuf_100.bin
ksec_pre_return_N/outbuf_100.bin   == advapi_ioctl_M/outbuf_100.bin
```

For this captured sequence, the checker reports:

```text
ksec_outbufs=16
advapi_ioctl_outbufs=8
exact_matches=16
```

## Sample groups

```text
vlh_01..vlh_08
```

VLH exit snapshots containing the observed `seedbase_after` region.

```text
ksec_entry_01..ksec_entry_07
```

KSecDD `NewGenRandomEx` entry snapshots.

```text
ksec_after_gather_01..ksec_after_gather_08
```

KSecDD output buffers observed after `GatherRandomKey`.

```text
ksec_pre_return_01..ksec_pre_return_08
```

KSecDD output buffers observed immediately before `NewGenRandomEx` returns.

```text
advapi_ioctl_01..advapi_ioctl_16
```

ADVAPI-side IOCTL buffers. The matching output buffers are the ones selected by
the checker and reported in `reports/sample01.ksec_advapi.txt`.

## Recheck

From the campaign root:

```bash
python3 scripts/check_ksec_newgen_to_advapi_ioctl.py \
  samples/sample01 \
  --csv reports/sample01.recheck.ksec_advapi.csv
```
