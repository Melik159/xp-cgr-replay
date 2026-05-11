# seed2state_v29_g_composed_provider_bridge

Composed provider-side validation campaign for the Windows XP SP3 `rsaenh.dll`
RNG path.

This campaign captures and replays, in a single execution, the provider-side
relation previously decomposed across narrower campaigns.

The validated composed relation is:

```text
G_provider =
  G_init
  + G_acquire_bridge_00
  + G_runtime_measured
````

The trace shows that the first measured `CryptGenRandom(32)` state is not
immediately adjacent to the provider initialization state. One additional
provider transition occurs during `CryptAcquireContext`.

Once this acquire-bridge transition is included, the provider state chain is
replayed sequentially through the same `rsaenh` FIPS-style block, and the
measured `CryptGenRandom(32)` output is reproduced as `runtime_out40[:32]`.

## Scope

This campaign is provider-side and composed.

It validates, for the captured execution:

```text
post-AlgorithmCheck state20
→ init provider transition
→ acquire-bridge provider transition
→ measured runtime provider transition
→ CryptGenRandom(32) output
→ next runtime provider state20
```

It does not, by itself, claim full upstream closure of the KSecDD / ADVAPI /
SystemFunction036 provenance. The upstream `SystemFunction036` path is handled
by separate ADVAPI/KSecDD campaigns.

## Validated relation

Each provider transition has the same local shape:

```text
state20_before @ rsaenh+0x31958
+ aux20_final
→ rsaenh FIPS-style block @ rsaenh+0x27101
→ out40
→ state20_after @ rsaenh+0x31958
```

where:

```text
aux20_final = SystemFunction036_raw20 XOR outbuf_prefix20
```

In this campaign, `outbuf_prefix20` is stored as the effective observed XOR
mask between the raw `SystemFunction036` output and the final `aux20` input
passed to the FIPS-style block.

## Captured transition sequence

The redacted trace captures the following provider-side sequence:

```text
AlgorithmCheck / self-test FIPS transition
  observed but excluded from the composed G sample

CryptAcquireContext
→ rsaenh+0x120CF
→ rsaenh+0x0D640
→ SystemFunction036([local_aux20], 0x14)
→ local XOR mix
→ rsaenh+0x27101(state=rsaenh+0x31958, aux=local_aux20, out=local_out40)
→ init_out40
→ init_state20_after
→ return rsaenh+0x120D4

CryptAcquireContext acquire-bridge
→ rsaenh+0x0D640
→ SystemFunction036([local_aux20], 0x14)
→ local XOR mix
→ rsaenh+0x27101(state=rsaenh+0x31958, aux=local_aux20, out=local_out40)
→ bridge00_out40
→ bridge00_state20_after
→ return rsaenh+0x0D766

CryptGenRandom(32)
→ rsaenh+0x0D7D5
→ rsaenh+0x0D640
→ SystemFunction036([local_aux20], 0x14)
→ local XOR mix
→ rsaenh+0x27101(state=rsaenh+0x31958, aux=local_aux20, out=local_out40)
→ runtime_out40
→ measured CGR output = runtime_out40[:32]
→ runtime_state20_after
→ return rsaenh+0x0D7DA
```

## Files

```text
harness/
  rng_test_v29_gbridge.c

windbg/
  v29_capture_commands.txt
  manual_after_measured_cgr_dump.txt

logs/
  v29_g_composed_provider_bridge.redacted.log

parser/
  parse_seed2state_v29_g_composed_provider_bridge.py

tools/
  redact_v29_log.py
  replay_v29_g_composed_provider_bridge.py

samples/sample01/blobs/
  init_state20_before.bin
  init_sysfunc036_raw20.bin
  init_outbuf_prefix20.bin
  init_aux20_final.bin
  init_out40.bin
  init_state20_after.bin

  bridge00_state20_before.bin
  bridge00_sysfunc036_raw20.bin
  bridge00_outbuf_prefix20.bin
  bridge00_aux20_final.bin
  bridge00_out40.bin
  bridge00_state20_after.bin

  runtime_state20_before.bin
  runtime_sysfunc036_raw20.bin
  runtime_outbuf_prefix20.bin
  runtime_aux20_final.bin
  runtime_out40.bin
  runtime_state20_after.bin

  cgr_output32.bin

samples/sample01/
  manifest.json
  manifest.tsv
  README.md
  v29_g_composed_validation.json
  v29_g_composed_validation.txt
```

## Capture outline

Use a trigger program that performs no warmup and exactly one measured
`CryptGenRandom(32)` after `CryptAcquireContext`.

Recommended harness sequence:

```text
int3 before CryptAcquireContext
CryptAcquireContextA(PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
int3 before measured CryptGenRandom
CryptGenRandom(32)
int3 after measured CryptGenRandom
```

At the first `int3`, run:

```text
windbg/v29_capture_commands.txt
```

At the final `int3` after the measured call, dump the measured output buffer:

```text
.echo [V29_CGR_OUTPUT32]
r
db @ebx L20
.logclose
```

The optional harness in `harness/` attempts to leave `EBX` pointing to the
32-byte measured output buffer at the final `int3`.

## Redact the log

Keep the raw log private. Publish only the redacted trace excerpt:

```bash
python3 tools/redact_v29_log.py \
  _private/v29_g_composed_provider_bridge_raw.log \
  logs/v29_g_composed_provider_bridge.redacted.log
```

## Reproduce sample extraction

From the campaign root:

```bash
rm -rf samples/sample01

python3 parser/parse_seed2state_v29_g_composed_provider_bridge.py \
  logs/v29_g_composed_provider_bridge.redacted.log \
  --write-sample samples/sample01 \
  --json /tmp/v29_g_composed_provider_bridge_parse.json
```

Expected parser summary:

```text
[V29_PARSE_OK]
init_ret=0x680120d4
bridge00_ret=0x6800d766
runtime_ret=0x6800d7da
```

## Replay validation

```bash
python3 tools/replay_v29_g_composed_provider_bridge.py \
  samples/sample01 \
  --json samples/sample01/v29_g_composed_validation.json \
  | tee samples/sample01/v29_g_composed_validation.txt
```

Expected checks:

```text
init_aux20_final_calc_equals_observed                PASS
init_out40_calc_equals_observed                      PASS
init_state20_after_calc_equals_observed              PASS
state_continuity_init_to_bridge00                    PASS
bridge00_aux20_final_calc_equals_observed            PASS
bridge00_out40_calc_equals_observed                  PASS
bridge00_state20_after_calc_equals_observed          PASS
state_continuity_bridge00_to_runtime                 PASS
runtime_aux20_final_calc_equals_observed             PASS
runtime_out40_calc_equals_observed                   PASS
runtime_state20_after_calc_equals_observed           PASS
cgr_output32_equals_runtime_out40_prefix             PASS
OVERALL=PASS
```

## Interpretation

This campaign validates the composed provider-side `G` relation in one captured
execution.

The direct relation:

```text
init_state20_after == runtime_state20_before
```

is not true for this trace.

Instead, the captured provider state continuity is:

```text
init_state20_after      == bridge00_state20_before
bridge00_state20_after  == runtime_state20_before
runtime_out40[:32]      == measured CryptGenRandom(32) output
```

Therefore the closed provider-side relation is:

```text
post-AlgorithmCheck state20
+ init SystemFunction036-derived aux20
→ init_state20_after

init_state20_after
+ bridge00 SystemFunction036-derived aux20
→ bridge00_state20_after

bridge00_state20_after
+ runtime SystemFunction036-derived aux20
→ measured CGR output and runtime_state20_after
```

This is stronger than the narrower provider-local campaigns because the
initialization, acquire-bridge, and measured runtime transitions are linked by
direct state continuity in the same trace.

## Claim boundary

This campaign supports the following claim:

```text
The provider-side G relation is closed as a composed replay in one execution:
post-AlgorithmCheck state20 is transformed through init, acquire-bridge, and
runtime provider transitions, all replayed through the same rsaenh FIPS-style
block, and the measured CryptGenRandom output is reproduced as runtime_out40[:32].
```

It does not claim full closure of the complete upstream path:

```text
KSecDD → ADVAPI → SystemFunction036 → rsaenh
```

That wider relation is addressed by separate ADVAPI/KSecDD campaigns.

## Checksum verification

If `SHA256SUMS` is present:

```bash
sha256sum -c SHA256SUMS
```

