# ADVAPI Round-Robin and Downstream Output

Original identifier: `seed2state_v5_roundrobin`  
Status: **PASS**  
Capture availability: reduced parsed result; collection scripts omitted.

This campaign validates the retained ADVAPI eight-state round-robin behavior,
selected non-zero RC4 PRGA calls, the relation to `SystemFunction036`, and the
retained provider `aux20` observation.

```bash
python3 validate.py
```

The campaign does not independently reconstruct the upstream KSecDD derivation
of every IOCTL buffer.

