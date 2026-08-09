# Composed Provider Bridge

Original identifier: `seed2state_v29_g_composed_provider_bridge`  
Status: **PASS**  
Capture availability: redacted log.

The parser regenerates the normalized sample from the retained log. The replay
checks the provider initialization transition, acquisition bridge transition,
runtime transition, both state-continuity relations, and equality between the
first 32 runtime output bytes and the measured `CryptGenRandom(32)` output.

```bash
python3 validate.py
```

This is the strongest provider-side campaign, but it does not close the full
upstream KSecDD/ADVAPI/SystemFunction036 provenance chain.

