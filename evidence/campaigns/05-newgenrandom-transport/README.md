# NewGenRandom Transport

Original identifier: `seed2state_v20_1_precise_newgenrandomex_outbuf`  
Status: **PASS**  
Capture availability: redacted log.

The retained log regenerates 94 sample files and the published event stream.
For eight distinct 256-byte values, validation requires exact equality at:

```text
KSecDD after GatherRandomKey
  -> KSecDD NewGenRandomEx pre-return
  -> ADVAPI IOCTL output
```

```bash
python3 validate.py
```

The campaign validates this transport observation only, not the upstream VLH
derivation or the downstream provider transition.

