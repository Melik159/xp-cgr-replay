# sample01

Extracted from the provider-initialization aux-mix WinDbg/KD trace.

Core relation:

```text
aux20_final = SystemFunction036_raw20 XOR outbuf_prefix20
FIPS186_block(state20_before, aux20_final) -> out40_init, state20_after
```
