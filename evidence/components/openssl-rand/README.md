# OpenSSL 0.9.8 Post-Stir Replay

Source directory: `ssleay/`.

The retained trace begins at `state_after_stir`. At state index 240, the replay
recomputes per-iteration SHA-1 digests, state XOR updates, and the final 32-byte
`RAND_bytes` output. Index 241 is the required negative control.

```bash
python3 validate.py --block 07-openssl-rand
```

The earlier Windows-input stirring phase is outside this component.

