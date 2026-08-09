# Block 07: OpenSSL Post-Stir RAND Output

This block starts from the retained OpenSSL 0.9.8 `state_after_stir` trace and
recomputes the `ssleay_rand_bytes()` byte-generation loop.

```bash
python3 validate.py
```

At state index 240, all per-iteration SHA-1 digests, XOR state updates, and the
final 32 bytes match. Index 241 is required to fail as a negative control.

The block does not reconstruct the earlier OpenSSL stirring process from the
Windows input captures.

