# seed2state_v22_writer_probe

This campaign contains a cleaned replay/check artifact for the `seed2state_v22_writer_probe` experiment.

The purpose of this campaign is to document first-write observations around the KSecDD `NewGenRandomEx` output buffer and to check their consistency with the retained KSecDD/ADVAPI transport samples.

This is a cleaned public artifact. The WinDbg collection scripts, raw log, breakpoint bodies, setup files, and local runtime scaffolding are intentionally not included.

## Scope

This artifact focuses on the following observed segment:

```text
VLH checkpoint / seedbase_after
→ KSecDD!NewGenRandomEx
→ output-buffer first-write observation
→ NewGenRandomEx after-gather / pre-return buffers
→ ADVAPI IOCTL after-c2 buffer
````

The retained parsed samples are stored in:

```text
results_v22_writer_probe/samples/
```

They include:

```text
vlh_*/
ksec_entry_*/
ksec_after_gather_*/
ksec_pre_return_*/
advapi_ioctl_*/
writer_*/
```

## What this campaign verifies

This campaign verifies that the observed writer checkpoints are consistent with the retained KSecDD/ADVAPI transport samples.

The main retained outputs are:

```text
results_v22_writer_probe/v22_writer_events.jsonl
results_v22_writer_probe/transport_check.txt
results_v22_writer_probe/writer_summary.txt
```

The `writer_*` samples capture the output buffer at or around the first observed write.

The campaign is useful because it narrows the observation point where the KSecDD output buffer begins to be populated during the `NewGenRandomEx` path.

## What this campaign does not verify

This campaign does not close the complete Windows XP `CryptGenRandom` provider function.

It does not reconstruct:

```text
seedbase_after → provider persistent state → state20
```

It also does not replace the separate final-provider-block replay:

```text
(state20, aux20) → out40
```

Its role is narrower: it documents where and how the KSecDD output buffer begins to be written, and checks that this observation is coherent with the retained transport artifacts.

## Directory layout

```text
parser/
  parse_seed2state_v22_writer_probe.py

tools/
  check_v22_writer_transport.py
  summarize_v22_writer_probe.py

results_v22_writer_probe/
  parse.stdout.txt
  samples/
  transport_check.txt
  v22_writer_events.jsonl
  writer_summary.txt

sanity_v22_writer_probe/
  log.lines.txt
  log.sha256
  log.size.txt
  marker_counts.txt
  timeline_core.txt
  writer_hits.txt

run_tests.sh
SHA256SUMS
```

The original raw log is omitted from the cleaned artifact. The files under `sanity_v22_writer_probe/` are derived summaries and provenance checks from that omitted log.

## Reproduce checks

Run:

```bash
./run_tests.sh
```

Manual integrity check:

```bash
sha256sum -c SHA256SUMS
```

The expected result is that all listed files verify successfully and the retained JSON/JSONL files parse correctly.

## Interpretation

This campaign should be cited as:

```text
V22 writer-probe validation around the KSecDD NewGenRandomEx output buffer
```

not as:

```text
complete CryptGenRandom replay
```

The remaining open component is still:

```text
seedbase_after / provider persistent state → state20
```

