#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib


def load_manifest(sample_dir: pathlib.Path):
    path = sample_dir / "manifest.json"
    if not path.exists():
        raise SystemExit(f"missing manifest: {path}")
    return json.loads(path.read_text())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_dir", help="samples/sample01")
    args = ap.parse_args()

    sample_dir = pathlib.Path(args.sample_dir)
    manifest = load_manifest(sample_dir)

    out40_by_copy = {}
    dest_by_copy = {}

    for m in manifest:
        ci = m.get("copy_index")
        if ci is None:
            continue

        if m["marker"] == "V26_OUT40_LOCAL_AFTER_COPY_EBP_M40":
            out40_by_copy[ci] = m

        if m["marker"] == "V26_OUT_DEST_AFTER_COPY":
            dest_by_copy[ci] = m

    copy_indexes = sorted(set(out40_by_copy) & set(dest_by_copy))

    if not copy_indexes:
        print("FAIL: no paired output-copy samples found")
        return 1

    passed = 0

    for ci in copy_indexes:
        o = out40_by_copy[ci]
        d = dest_by_copy[ci]

        out40 = (sample_dir / o["file"]).read_bytes()
        dest = (sample_dir / d["file"]).read_bytes()

        copy_len = d.get("copy_len") or len(dest)
        if copy_len <= 0:
            copy_len = len(dest)

        # Destination samples are truncated to copy_len by the extractor.
        # Out40 samples remain up to 40 bytes.
        ok = len(dest) == copy_len and out40[:copy_len] == dest

        print(
            f"copy#{ci} "
            f"len={copy_len} "
            f"out40={o['file']} "
            f"dest={d['file']} "
            f"status={'PASS' if ok else 'FAIL'}"
        )

        if ok:
            passed += 1
        else:
            print(f"  out40[:len]={out40[:copy_len].hex()}")
            print(f"  dest       ={dest.hex()}")
            print(f"  dest_size  ={len(dest)} expected_len={copy_len}")

    print(f"summary PASS={passed}/{len(copy_indexes)}")
    return 0 if passed == len(copy_indexes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
