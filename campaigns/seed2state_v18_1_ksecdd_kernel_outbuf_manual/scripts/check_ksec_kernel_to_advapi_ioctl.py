#!/usr/bin/env python3
import argparse,csv,json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("samples_dir")
    ap.add_argument("--csv")
    args=ap.parse_args()
    root=Path(args.samples_dir)
    ksecs=[]
    for f in sorted(root.glob("ksec_*/V18_1_MANUAL_KSEC_KERNEL_OUTBUF_100.bin")):
        b=f.read_bytes()
        if len(b)>=256:
            ksecs.append((f.parent.name,b[:256]))
    ioctls=[]
    for f in sorted(root.glob("ioctl_*/V18_1_IOCTL_OUTBUF_100.bin")):
        b=f.read_bytes()
        if len(b)>=256:
            ioctls.append((f.parent.name,b[:256]))
    rows=[]
    print("[V18.1 KSECDD KERNEL OUTBUF -> ADVAPI IOCTL CHECK]")
    print(f"ksec_kernel_outbufs={len(ksecs)}")
    print(f"ioctl_outbufs={len(ioctls)}\n")
    for kn,kb in ksecs:
        for iname,ib in ioctls:
            if kb == ib:
                rows.append({"ksec":kn,"ioctl":iname,"kind":"exact_256"})
                print(f"MATCH {kn} == {iname}")
    print("\n[SUMMARY]")
    print(f"ksec_kernel_to_ioctl_exact_matches={len(rows)}")
    if not rows:
        print("No exact KSecDD kernel_outbuf == ADVAPI IOCTL outbuf match in parsed samples.")
    if args.csv:
        with open(args.csv,"w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=["ksec","ioctl","kind"])
            w.writeheader(); w.writerows(rows)
        print(f"csv={args.csv}")
if __name__=="__main__":
    main()
