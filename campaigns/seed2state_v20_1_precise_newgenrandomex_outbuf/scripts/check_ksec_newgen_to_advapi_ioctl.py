#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

def read_candidates(root: Path, globpat: str):
    out = []
    for f in sorted(root.glob(globpat)):
        b = f.read_bytes()
        if len(b) >= 256:
            out.append((f.parent.name, f.name, b[:256], f))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("samples_dir")
    ap.add_argument("--csv")
    args = ap.parse_args()

    root = Path(args.samples_dir)

    ksecs = []
    ksecs += read_candidates(root, "ksec_after_gather_*/outbuf_100.bin")
    ksecs += read_candidates(root, "ksec_common_post_*/outbuf_100.bin")
    ksecs += read_candidates(root, "ksec_pre_return_*/outbuf_100.bin")

    adv = read_candidates(root, "advapi_ioctl_*/outbuf_100.bin")

    rows = []
    print("[V20.1 KSECDD NEWGENRANDOMEX OUTBUF -> ADVAPI IOCTL CHECK]")
    print(f"ksec_outbufs={len(ksecs)}")
    print(f"advapi_ioctl_outbufs={len(adv)}")
    print()

    for kn, kfile, kb, kpath in ksecs:
        for an, afile, ab, apath in adv:
            if kb == ab:
                row = {
                    "ksec": kn,
                    "ksec_file": str(kpath),
                    "advapi": an,
                    "advapi_file": str(apath),
                    "kind": "exact_256",
                    "head16": kb[:16].hex(),
                }
                rows.append(row)
                print(f"MATCH {kn}/{kfile} == {an}/{afile} head16={kb[:16].hex()}")

    print()
    print(f"[SUMMARY] exact_matches={len(rows)}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            fieldnames = ["ksec", "ksec_file", "advapi", "advapi_file", "kind", "head16"]
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)
        print(f"csv={args.csv}")

if __name__ == "__main__":
    main()
