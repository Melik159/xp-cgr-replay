# Block 05: rsaenh Provider State

This block validates provider-local state transitions using V19c, V26, V28,
and V29.

```bash
python3 validate.py
```

V28 and V29 regenerate their normalized samples from retained redacted logs.
V29 validates the composed initialization, acquisition bridge, runtime state
continuity, and measured 32-byte output in one captured execution.

The block begins from captured provider-side inputs. It does not prove their
complete upstream provenance through KSecDD, ADVAPI, and
`SystemFunction036`.

