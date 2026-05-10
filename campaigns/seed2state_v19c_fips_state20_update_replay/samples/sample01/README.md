# sample01

This directory contains the extracted V19C tuples for the captured sequence.

Each `call_XXX/` directory contains:

```text
state20_before.bin
state20_before.hex
aux20.bin
aux20.hex
out40_after.bin
out40_after.hex
state20_after.bin
state20_after.hex
meta.json
```

Replay relation:

```text
state20_before + aux20
→ FIPS replay
→ out40_after + state20_after
```

Expected result:

```text
out40_match=5/5
state20_after_match=5/5
state20_after_eq_core_exit=5/5
recurrence_match=4/4
replay_ok=5/5

v19c_provider_state_update_closed=True
```
