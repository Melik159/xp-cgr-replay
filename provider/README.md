# Provider XOR and FIPS-style Replay

This module validates a portion of the provider-side construction used by
`CryptGenRandom` on Windows XP SP3.

It focuses on two experimentally observed relations:

## 1. Local XOR stage

```text
local_before XOR src20 = aux20 (= local_after)
```

This relation is directly validated from memory traces.

## 2. High-level FIPS-style construction

```text
(state20, aux20) → out40 → cgr_0x20
```

This stage models the transformation observed in the provider after the
kernel phase, combining arithmetic over 160-bit values and SHA-1 compression.

---

## Description

The script `provider_xor_fips_replay.py` performs the following steps:

- Reconstructs `aux20` from `local_before` and `src20`
- Verifies consistency with `local_after` (if provided)
- Computes the 40-byte output buffer `out40`
- Extracts the final 32-byte output `cgr_0x20`

This corresponds to the provider-side processing observed after the
`KSecDD` kernel contribution.

---

## Usage

```bash
python3 provider_xor_fips_replay.py \
  --state20-file sample01/state20.bin \
  --local-before-file sample01/local_before.bin \
  --src20-file sample01/src20.bin \
  --local-after-file sample01/local_after.bin
```

---

## Expected Output

```text
[PROVIDER_LOCAL_XOR_REPLAY]
aux20         : <value>
xor_match     : OK
```

The `xor_match : OK` confirms:

```text
local_before XOR src20 = local_after
```

The script also prints intermediate reconstructed values:

- `tmp0`, `x0`, `part0`
- `tmp1`, `x1`, `part1`
- `out40`
- `cgr_0x20`

---

## Notes

- The FIPS-style computation implemented here is a **high-level replay**.
- It reproduces the observed arithmetic and SHA-1 compression behavior,
  but **does not reconstruct the exact internal 64-byte block layout**.
- Precise block construction is validated separately in the `fips/` module.
- Cross-validation with `out40_after.bin` is only meaningful when all inputs
  originate from the **same execution trace**.

---

## Validation Scope

- ✔ XOR relation: fully validated (trace-consistent)
- ✔ FIPS transformation interface (`state20`, `aux20` → `out40`): validated
- ⚠ Internal block construction: modeled, not fully reconstructed here
