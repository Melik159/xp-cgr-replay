# NewGenRandom First-Write Observation

Original identifier: `seed2state_v22_writer_probe`  
Status: **PASS on retained events and samples**  
Capture availability: original collection log omitted.

The source package misplaced its 128 sample files relative to its README and
manifest. They are normalized here under `samples/`.

Validation requires eight complete cycles, a retained first-write buffer in
every cycle, writer EIP `f745f10b`, equality of the after/pre/ADVAPI transport
hashes, and resolution of every event dump hash to a retained binary.

```bash
python3 validate.py
```

Because the raw log is omitted, this is not a regeneration-from-capture claim.

