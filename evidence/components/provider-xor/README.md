# Provider-Local XOR Sample

Source directory: `provider/`.

Validated relation:

```text
local_before XOR src20 = local_after
```

The retained script also computes a high-level FIPS-style `out40`, but this
sample does not contain an observed `out40` reference. The normalized verdict
therefore covers the captured XOR relation only.

```bash
python3 validate.py --block 06-provider-primitives
```

