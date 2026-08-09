# KSecDD to ADVAPI Boundary

Original identifier: `seed2state_v18_1_ksecdd_kernel_outbuf_manual`  
Status: **PASS**  
Capture availability: redacted log.

The retained sample contains one exact 256-byte match between a manually
captured KSecDD kernel output buffer and an ADVAPI IOCTL output buffer. The
downstream sample also contains ten KSA matches and four useful PRGA replays.

```bash
python3 validate.py
```

The redacted log regenerates the retained binary evidence. Curated metadata
fields that are not emitted by the current parser are not used for the verdict.

