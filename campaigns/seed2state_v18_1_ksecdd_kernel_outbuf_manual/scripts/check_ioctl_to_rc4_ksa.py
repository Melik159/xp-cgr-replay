#!/usr/bin/env python3
import argparse,csv
from pathlib import Path

def ksa(key):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff
        S[i],S[j]=S[j],S[i]
    return bytes(S)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("samples_dir")
    ap.add_argument("--csv")
    args=ap.parse_args()
    root=Path(args.samples_dir)
    ioctls=[]
    for f in sorted(root.glob("ioctl_*/V18_1_IOCTL_OUTBUF_100.bin")):
        b=f.read_bytes()
        if len(b)>=256: ioctls.append((f.parent.name,b[:256]))
    states=[]
    for d in sorted(root.glob("prga_*")):
        p=d/"state_before_sij.bin"
        if p.exists():
            b=p.read_bytes()
            if len(b)>=258:
                states.append((d.name,b[:256],b[256],b[257]))
    rows=[]
    print("[V18.1 ADVAPI IOCTL OUTBUF -> RC4 KSA CHECK]")
    print(f"ioctl_outbufs={len(ioctls)}")
    print(f"states={len(states)}\n")
    for sname,S,i,j in states:
        for iname,ib in ioctls:
            if ksa(ib)==S:
                rows.append({"state":sname,"ioctl":iname,"i":f"{i:02x}","j":f"{j:02x}"})
                print(f"MATCH {iname} -> {sname} i={i:02x} j={j:02x}")
    print("\n[SUMMARY]")
    print(f"ioctl_to_rc4_ksa_matches={len(rows)}")
    if args.csv:
        with open(args.csv,"w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=["state","ioctl","i","j"])
            w.writeheader(); w.writerows(rows)
        print(f"csv={args.csv}")
if __name__=="__main__":
    main()
