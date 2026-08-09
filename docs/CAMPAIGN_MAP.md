# Campaign Map

The original numeric names describe the order of instrumentation experiments,
not a complete sequence of protocol stages. The reorganized names describe the
validated relation instead.

| New directory | Original campaign | Capture retained | Current status |
|---|---|---:|---|
| `01-advapi-round-robin` | `seed2state_v5_roundrobin` | reduced result only | PASS |
| `02-advapi-ioctl-to-rc4` | `seed2state_v17_1_precise_ioctl_outbuf` | full retained log | PASS |
| `03-ksecdd-to-advapi` | `seed2state_v18_1_ksecdd_kernel_outbuf_manual` | redacted log | PASS |
| `04-provider-state-update` | `seed2state_v19c_fips_state20_update_replay` | redacted log | PASS |
| `05-newgenrandom-transport` | `seed2state_v20_1_precise_newgenrandomex_outbuf` | redacted log | PASS |
| `06-newgenrandom-first-write` | `seed2state_v22_writer_probe` | omitted | PASS on retained events/samples |
| `07-ksecdd-rc4-transport` | `seed2state_v23_rc4_replay` | omitted | PASS on retained events/samples |
| `08-partial-advapi-transport` | `seed2state_v24_close_g_partial_advapi` | omitted | PARTIAL |
| `09-rsaenh-provider-transition` | `seed2state_v26_rsaenh_provider_only` | reduced excerpt | PASS |
| `10-provider-initialization` | `seed2state_v28_provider_init_auxmix` | redacted log | PASS |
| `11-provider-composed-bridge` | `seed2state_v29_g_composed_provider_bridge` | redacted log | PASS |

There were no public campaign directories V21, V25, or V27 in the source
artifact. No placeholder data has been created for those identifiers.

