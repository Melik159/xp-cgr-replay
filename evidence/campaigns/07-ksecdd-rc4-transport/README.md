# KSecDD RC4 Transport

Original identifier: `seed2state_v23_rc4_replay`  
Status: **PASS on retained events and samples**  
Capture availability: original collection log omitted.

Eight cycles must each contain one VLH checkpoint, two RC4 entries, two RC4
returns, one first-write observation, after-gather and pre-return buffers, and
an ADVAPI observation. Transport hashes must match, and every event dump hash
must resolve to a retained binary sample.

```bash
python3 validate.py
```

The validator does not reconstruct the omitted WinDbg collection run.

