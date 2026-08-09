# Data Provenance

The reorganized artifact was produced from the local source directory:

```text
/home/hal/Téléchargements/xp-cgr-replay-main
```

This path identifies the local assembly source; it is not part of any
scientific claim.

## Included content

All non-documentation campaign and component files were copied byte-for-byte,
then placed under descriptive English directory names. The selected source set
contains 1,144 files. Those same 1,144 byte-identical files are present in the
reorganized `evidence/` directory alongside new README and validation launcher
files.

## Excluded source files

The following were deliberately not copied:

- old README files, because they were replaced with normalized English files;
- old `SHA256SUMS` files, because several nested manifests were stale;
- obsolete shell launchers (`run_tests.sh` and `reproduce_sample01.sh`);
- Python bytecode caches;
- editor backup files ending in `~`.

The original Python parsers and replay tools remain retained. The excluded
shell files contained orchestration only and no measured data.

## Renamed V22 location

The V22 source package stored its 128 sample files under `samples/`, while its
README, nested manifest, and launcher referred to
`results_v22_writer_probe/samples/`. The reorganized repository uses the actual
location `samples/` and validates all event dump hashes against those binaries.

## Integrity files

- `SOURCE_FILE_MAP.tsv` records source path, reorganized path, and SHA-256
  for every retained evidence file.
- `SHA256SUMS` covers the completed reorganized repository except the manifest
  itself.
