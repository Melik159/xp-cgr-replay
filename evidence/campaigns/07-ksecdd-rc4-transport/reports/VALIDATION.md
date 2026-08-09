# V23 validation record

## Log identity

```text
12311 logs/v23_log_console.log
772K   logs/v23_log_console.log
81889a23bc32a828821a0c06610518b60398f283c42e41922dd27422aaaf291e  logs/v23_log_console.log
```

## Core timeline structure

The captured log shows eight NewGenRandomEx cycles.

Each cycle contains:

```text
1 NewGenRandomEx entry
1 VLH checkpoint
2 RC4 entries
2 RC4 returns
1 first write into the watched output buffer
1 NewGenRandomEx after-gather checkpoint
1 NewGenRandomEx pre-return checkpoint
1 ADVAPI IOCTL after-call checkpoint
```

## Transport validation

Validator output:

```text
cycle entry vlh rc4_entry rc4_return first_write after pre advapi transport_match status
01 27 1 2 2 1 1218 1379 1519 True PASS
02 1625 1 2 2 1 2764 2919 3053 True PASS
03 3153 1 2 2 1 4283 4438 4572 True PASS
04 4672 1 2 2 1 5811 5966 6100 True PASS
05 6200 1 2 2 1 7339 7494 7628 True PASS
06 7728 1 2 2 1 8867 9022 9156 True PASS
07 9256 1 2 2 1 10395 10550 10684 True PASS
08 10784 1 2 2 1 11923 12078 12212 True PASS
PASS=8/8
```

## Closed relation

The validated equality is:

```text
KSecDD NewGenRandomEx outbuf after_gather
==
KSecDD NewGenRandomEx outbuf pre_return
==
ADVAPI IOCTL outbuf
```

## Scientific statement

The V23 campaign provides an empirical, trace-backed validation of the
kernel-side output writer and transport path between KSecDD and ADVAPI.

It closes the following segment:

```text
KSecDD VLH/RC4/NewGenRandomEx → ADVAPI IOCTL output buffer
```

It does not close the later provider step:

```text
ADVAPI-side material → rsaenh provider persistent state/state20
```
