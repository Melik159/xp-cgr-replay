# FIPS-Style SHA-1 Compression Sample

Source directory: `fips/`.

Two retained 64-byte blocks are compressed with the standard SHA-1 compression
function. Their concatenated 40-byte result must match `out40_after.bin`. The
alternate non-standard transform is retained as a negative comparison and must
not match.

```bash
python3 validate.py --block 06-provider-primitives
```

The normalized wrapper is fail-closed even though the historical script only
printed its comparison result.

