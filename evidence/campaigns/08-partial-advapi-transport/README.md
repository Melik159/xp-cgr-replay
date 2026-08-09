# Partial ADVAPI Transport

Original identifier: `seed2state_v24_close_g_partial_advapi`  
Status: **PARTIAL**  
Capture availability: original collection log omitted.

The normalized validator uses retained event lengths and binary samples to
recompute:

- 16 RC4 KSA states;
- 16 RC4 PRGA outputs and resulting states;
- eight KSecDD after-gather/pre-return 256-byte equalities.

```bash
python3 validate.py
```

The full ADVAPI output-buffer capture is not trustworthy. The campaign is
therefore not described as a closure of the complete provider function or of
the full KSecDD-to-ADVAPI boundary.

