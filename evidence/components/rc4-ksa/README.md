# RC4 KSA Sample

Source directory: `rc4/`.

This component applies RC4 key scheduling to the retained 256-byte key material
and compares the resulting 256-byte permutation with the observed S-box.

```bash
python3 validate.py --block 06-provider-primitives
```

Expected relation: exact match across 2,048 S-box bits.

