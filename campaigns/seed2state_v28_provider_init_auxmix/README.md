# seed2state_v28_provider_init_auxmix

Provider-local initialization validation campaign for the Windows XP SP3
`rsaenh.dll` RNG path.

This campaign validates the provider initialization transition observed during
`CryptAcquireContext`.

The validated local relation is:

```text
post-AlgorithmCheck state20 @ 68031958
+ aux20_final
→ rsaenh FIPS-style block @ 68027101
→ out40_init
→ first runtime provider state20 @ 68031958
```

where:

```text
aux20_final = SystemFunction036_raw20 XOR outbuf_prefix20
```

## Scope

This campaign is intentionally provider-local.

It validates that the first runtime provider state is produced by the same
FIPS-style provider block used in the provider replay campaign, using an
`aux20` value derived from `SystemFunction036` and locally mixed with the
provider output-buffer prefix.

It does not, by itself, claim full upstream closure of the KSecDD / ADVAPI /
SystemFunction036 provenance. That upstream path is handled by the separate
ADVAPI and KSecDD campaigns.

## Captured transition

The redacted trace captures the following initialization path:

```text
rsaenh+0x120CF
→ rsaenh+0x0D640
→ SystemFunction036([ebp-0x18], 0x14)
→ local XOR mix
→ rsaenh+0x27101(
      state = rsaenh+0x31958,
      aux   = [ebp-0x18],
      out   = [ebp-0x40]
  )
→ out40_init
→ state20_after
→ return rsaenh+0x120D4
```

The key observed values are extracted into `samples/sample01/blobs/`.

## Files

```text
logs/
  g_state_init_aux_confirm.redacted.log

parser/
  parse_seed2state_v28_provider_init_auxmix.py

tools/
  redact_v28_log.py
  replay_v28_provider_init_auxmix.py

samples/sample01/blobs/
  state20_before.bin
  sysfunc036_raw20.bin
  outbuf_prefix20.bin
  aux20_final.bin
  out40_init.bin
  state20_after.bin

samples/sample01/
  manifest.json
  manifest.tsv
  v28_provider_init_auxmix_validation.json
  v28_provider_init_auxmix_validation.txt
```

## Reproduce sample extraction

From the campaign root:

```bash
python3 parser/parse_seed2state_v28_provider_init_auxmix.py \
  logs/g_state_init_aux_confirm.redacted.log \
  --write-sample samples/sample01 \
  --json /tmp/v28_provider_init_auxmix_parse.json
```

## Replay validation

```bash
python3 tools/replay_v28_provider_init_auxmix.py \
  samples/sample01 \
  --json samples/sample01/v28_provider_init_auxmix_validation.json \
  | tee samples/sample01/v28_provider_init_auxmix_validation.txt
```

Expected result:

```text
aux20_final_calc_equals_observed             PASS
out40_calc_equals_observed                   PASS
state20_after_calc_equals_observed           PASS
OVERALL=PASS
```

The replay report prints both observed and calculated values, including:

```text
[OBSERVED]
  state20_before
  sysfunc036_raw20
  outbuf_prefix20
  aux20_final_obs
  out40_obs
  state20_after_obs

[CALCULATED]
  aux20_final_calc = sysfunc036_raw20 XOR outbuf_prefix20
  xval_A
  out20_A
  state_A
  xval_B
  out20_B
  out40_calc
  state20_after_calc
```

## Validated relations

This campaign validates the following local relations:

```text
aux20_final = sysfunc036_raw20 XOR outbuf_prefix20
```

```text
out40_init = FIPS_provider_block(state20_before, aux20_final)
```

```text
state20_after = FIPS_provider_update(state20_before, aux20_final)
```

For `sample01`, the replay checks:

```text
[aux20_final] PASS
  obs  = 31 0c ca d9 cd 97 0d 21 10 7a f1 8d 26 6b 4c 21 df 88 34 46
  calc = 31 0c ca d9 cd 97 0d 21 10 7a f1 8d 26 6b 4c 21 df 88 34 46

[out40_init] PASS
  obs  = 56 e5 7e 14 56 8b 32 54 08 6d 9a 3f f8 72 4b a5 a9 43 0e c4 f9 9d be bf 65 01 6d cd dd fe 57 f7 04 67 cc af 9f 8a 11 c9
  calc = 56 e5 7e 14 56 8b 32 54 08 6d 9a 3f f8 72 4b a5 a9 43 0e c4 f9 9d be bf 65 01 6d cd dd fe 57 f7 04 67 cc af 9f 8a 11 c9

[state20_after] PASS
  obs  = 75 48 43 93 ff e8 21 9a 54 35 0e bc 6a e8 0e 15 c5 55 25 7a
  calc = 75 48 43 93 ff e8 21 9a 54 35 0e bc 6a e8 0e 15 c5 55 25 7a
```

## Interpretation

This campaign shows that the initial runtime provider state is not copied from
an unexplained external `state20` source during the captured initialization
path.

Instead, after `AlgorithmCheck`, `rsaenh.dll` calls the provider RNG wrapper
from the DLL/provider initialization path. The wrapper obtains 20 bytes from
`SystemFunction036`, mixes them locally with the provider output-buffer prefix,
and feeds the resulting `aux20_final` into the provider FIPS-style block.

The block produces `out40_init` and updates the provider global state slot
`rsaenh+0x31958` to the first runtime provider state.

## Relation to the wider G decomposition

This campaign contributes to the decomposition of the provider-side state
relation `G`.

In this campaign:

```text
G_init provider-local transition:
  post-AlgorithmCheck state20
  + (SystemFunction036_raw20 XOR outbuf_prefix20)
  → rsaenh FIPS-style block
  → first runtime state20
```

This should not be read as a standalone end-to-end closure of the entire
KSecDD → ADVAPI → rsaenh path. It closes the provider-local initialization
transition given the observed `SystemFunction036` output.

The upstream provenance of `SystemFunction036` is addressed by the separate
ADVAPI/KSecDD campaigns.

## Checksum verification

If `SHA256SUMS` is present:

```bash
sha256sum -c SHA256SUMS
```
