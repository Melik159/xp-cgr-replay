# Block 03: KSecDD and ADVAPI Transport

This block groups five experiments around `KSecDD!NewGenRandomEx`, RC4 output
buffers, first-write observations, and ADVAPI-side IOCTL buffers.

```bash
python3 validate.py
```

Validated results:

- V18.1: one exact KSecDD-to-ADVAPI 256-byte boundary match;
- V20.1: eight distinct after-gather/pre-return/ADVAPI triplets;
- V22: eight complete writer cycles with retained writer buffers;
- V23: eight structurally complete RC4 transport cycles;
- V24: 16 KSA and 16 PRGA replays plus eight KSecDD after/pre pairs.

V24 remains `PARTIAL` because its full 256-byte ADVAPI output buffer was not
captured reliably.

