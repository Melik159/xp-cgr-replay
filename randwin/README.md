# randwin / Windows RAND_poll input decoder

This directory contains a structural decoder, sorter, and validator for
`randwin_full.json` files captured around the Windows OpenSSL
`RAND_poll` / `ssleay_rand_bytes` path.

The scope of this tool is deliberately limited.

It decodes selected Win32 records, checks record coherence, compares
sources across runs, and provides specialized views for modules, processes,
threads, heaps, Lanman records, memory records, timing records, and opaque
byte blobs.

It does not concatenate all Windows inputs and does not claim to replay the
OpenSSL PRNG state transition.

`CryptGenRandom` records are not decoded as Win32 structures. They are
reported only as opaque byte blobs by length, SHA-256, and byte preview.

## Directory layout

```text
randwin/
├── decode_randwin_full.py
├── README.md
├── sample01/
│   └── randwin_full.json
├── sample02/
│   └── randwin_full.json
└── sample03/
    └── randwin_full.json
```

## Input modes

The decoder supports both single-file and multi-run directory inputs.

Single file:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --summary --validate
```

Directory with immediate sample folders:

```bash
python3 decode_randwin_full.py . --summary --validate
```

Recursive directory scan:

```bash
python3 decode_randwin_full.py . --recursive --summary --validate
```

Recursive mode searches for files named:

```text
randwin_full.json
```

## Help

Display the complete command-line interface:

```bash
python3 decode_randwin_full.py -h
```

## Supported sources

The decoder currently handles the following record families:

```text
LanmanWorkstation
LanmanServer
CryptGenRandom
GetForegroundWindow
GetCursorInfo
GetQueueStatus
Heap32List
Heap32Entry
ProcessEntry
ThreadEntry
ModuleEntry
QueryPerformanceCounter
GlobalMemoryStatus
GetCurrentProcessId
```

Known Win32 structures are decoded field by field.

Unknown or opaque records are preserved as raw byte records and are still
checked for metadata consistency.

## Summary view

Print per-run source counts and captured byte totals:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --summary
python3 decode_randwin_full.py . --recursive --summary
```

The summary includes:

```text
- number of records
- total captured bytes
- number of sources
- per-source record count
- per-source byte count
```

## Validation

Run structural and semantic validation:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --validate
python3 decode_randwin_full.py . --recursive --validate
```

The validation checks include:

```text
- JSON top-level object is a list
- record index matches array position
- required record keys are present
- hex payload is valid
- decoded byte length matches metadata length
- known Win32 structures have expected sizes
- ProcessEntry.szExeFile is non-empty
- ModuleEntry.szModule is non-empty
- GlobalMemoryStatus.dwLength equals 32
- QueryPerformanceCounter values do not decrease within a run
- GetCurrentProcessId values are cross-checked against ProcessEntry PIDs
```

JSON validation output:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --validate --json
```

## Source comparison

Compare source presence, record counts, and byte counts across runs:

```bash
python3 decode_randwin_full.py . --recursive --compare-sources
```

## Coherence view

Print combined coherence tables:

```bash
python3 decode_randwin_full.py . --recursive --coherence
```

The coherence view includes:

```text
- input files and record counts
- source matrix
- module matrix
- CryptGenRandom blob matrix
- validation status by run
```

## Module views

Print raw `ModuleEntry` records:

```bash
python3 decode_randwin_full.py . --recursive --modules
```

Filter modules by text:

```bash
python3 decode_randwin_full.py . --recursive --modules --grep advapi
python3 decode_randwin_full.py . --recursive --modules --grep bitcoin
python3 decode_randwin_full.py . --recursive --modules --grep dll
```

Print de-duplicated module rows per run/module/base/path/PID:

```bash
python3 decode_randwin_full.py . --recursive --modules-unique
```

Sort de-duplicated modules:

```bash
python3 decode_randwin_full.py . --recursive --modules-unique --sort module,base
python3 decode_randwin_full.py . --recursive --modules-unique --sort snapshots --desc
python3 decode_randwin_full.py . --recursive --modules-unique --sort first_index
```

Print only the module presence matrix:

```bash
python3 decode_randwin_full.py . --recursive --modules-presence
python3 decode_randwin_full.py . --recursive --modules-presence --sort entries --desc
```

Append an aggregate matrix after detailed module rows:

```bash
python3 decode_randwin_full.py . --recursive --modules-unique --aggregate
```

Supported module sort keys:

```text
--modules:
  run,index,module,base,size,path,pid

--modules-unique:
  run,index,module,base,size,path,pid,snapshots,first_index,last_index

--modules-presence:
  module,runs,bases,paths,entries
```

## Process view

Print decoded `ProcessEntry` records:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --processes
python3 decode_randwin_full.py . --recursive --processes
```

Filter process rows:

```bash
python3 decode_randwin_full.py . --recursive --processes --grep bitcoin
```

## Thread view

Print decoded `ThreadEntry` records and owner counts:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --threads
python3 decode_randwin_full.py . --recursive --threads
```

## Heap view

Print decoded `Heap32List` and `Heap32Entry` records:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --heaps
python3 decode_randwin_full.py . --recursive --heaps
```

## Lanman view

Print decoded `LanmanWorkstation` and `LanmanServer` records:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --lanman
python3 decode_randwin_full.py . --recursive --lanman
```

## Memory view

Print decoded `GlobalMemoryStatus` records:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --memory
python3 decode_randwin_full.py . --recursive --memory
```

## Timing view

Print timing and small scalar records:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --timing
python3 decode_randwin_full.py . --recursive --timing
```

The timing view includes records from:

```text
QueryPerformanceCounter
GetQueueStatus
GetForegroundWindow
GetCurrentProcessId
```

## Opaque blob view

Print opaque byte records by length, SHA-256, and preview:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --blobs
python3 decode_randwin_full.py . --recursive --blobs
```

`CryptGenRandom` records are displayed in this form:

```text
run=<run> index=<index> source=CryptGenRandom length=<n> sha256=<digest> first16=<hex>
```

The tool does not decode `CryptGenRandom` as a structure.

## Generic source decoding

Decode only one selected source:

```bash
python3 decode_randwin_full.py sample01/randwin_full.json --source LanmanWorkstation
python3 decode_randwin_full.py sample01/randwin_full.json --source Heap32Entry --limit 5
python3 decode_randwin_full.py sample01/randwin_full.json --source ModuleEntry
```

The selected records are emitted as JSON objects.

## Filtering and limiting

Most specialized textual views support case-insensitive filtering:

```bash
python3 decode_randwin_full.py . --recursive --modules --grep advapi
python3 decode_randwin_full.py . --recursive --processes --grep bitcoin
```

Limit the number of printed rows:

```bash
python3 decode_randwin_full.py . --recursive --modules --limit 10
python3 decode_randwin_full.py sample01/randwin_full.json --source Heap32Entry --limit 5
```

## Reproducibility boundary

This module validates and compares captured Windows input records.

The replay of `ssleay_rand_bytes` and the final byte-generation path belongs
to the adjacent OpenSSL/SSLeay tooling. This separation keeps the Windows
input inspection layer distinct from OpenSSL PRNG state replay.

```text
randwin/  -> decode, sort, compare, and validate Windows input records
ssleay/   -> replay and validate the OpenSSL/SSLeay byte-generation path
```

## Minimal test set

After modifying the script, run:

```bash
python3 -m py_compile decode_randwin_full.py
python3 decode_randwin_full.py -h
python3 decode_randwin_full.py . --recursive --summary --validate
python3 decode_randwin_full.py . --recursive --modules-unique --sort module,base
python3 decode_randwin_full.py . --recursive --modules-presence --sort entries --desc
python3 decode_randwin_full.py . --recursive --coherence
python3 decode_randwin_full.py sample01/randwin_full.json --blobs
```
