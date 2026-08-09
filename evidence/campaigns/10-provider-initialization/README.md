# Provider Initialization

Original identifier: `seed2state_v28_provider_init_auxmix`  
Status: **PASS**  
Capture availability: redacted log.

The parser regenerates the normalized sample byte-for-byte from the retained
log. The replay checks the auxiliary XOR, initialization `out40`, and resulting
provider state.

```bash
python3 validate.py
```

This provider-local initialization does not establish the complete upstream
provenance of the `SystemFunction036` input.

