#!/usr/bin/env python3
import argparse,csv,json
from pathlib import Path

def ksa(key):
    S=list(range(256)); j=0
    if not key: return bytes(S)
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff
        S[i],S[j]=S[j],S[i]
    return bytes(S)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("samples_dir")
    ap.add_argument("--csv")
    ap.add_argument("--lengths",default="16,20,32,40,64,80,100,128,240,256")
    args=ap.parse_args()
    lengths=[int(x,0) for x in args.lengths.split(",") if x]
    root=Path(args.samples_dir)
    ioctls=[]
    for f in sorted(root.glob("ioctl_*/V17_1_IOCTL_OUTBUF_100.bin")):
        b=f.read_bytes()
        if b:
            ioctls.append((f.relative_to(root).as_posix(),b))
    states=[]
    for d in sorted(root.glob("prga_*")):
        p=d/"state_before_sij.bin"
        if p.exists():
            b=p.read_bytes()
            if len(b)>=258:
                states.append((d.name,b[:256],b[256],b[257]))
    rows=[]
    print("[V17.1 PRECISE IOCTL-OUTBUF -> RC4 KSA SCAN]")
    print(f"samples_dir={args.samples_dir}")
    print(f"ioctl_outbufs={len(ioctls)}")
    print(f"states={len(states)}")
    print(f"lengths={lengths}\n")
    for sname,S,i,j in states:
        for fname,buf in ioctls:
            for L in lengths:
                if len(buf)<L: continue
                for off in range(0,len(buf)-L+1):
                    key=buf[off:off+L]
                    if ksa(key)==S:
                        r={"state":sname,"i":f"{i:02x}","j":f"{j:02x}","outbuf":fname,"offset":off,"length":L,"key_hex":key.hex()}
                        rows.append(r)
                        print(f"MATCH state={sname} outbuf={fname} off={off} len={L} i={i:02x} j={j:02x}")
    print("\n[SUMMARY]")
    print(f"direct_ksa_matches={len(rows)}")
    if not rows:
        if ioctls:
            print("No direct RC4 KSA match from captured precise IOCTL outbufs.")
            print("Interpretation: direct raw KSA over tested IOCTL outbuf windows is not supported.")
        else:
            print("No IOCTL outbufs available; scan is inconclusive.")
    if args.csv:
        with open(args.csv,"w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=["state","i","j","outbuf","offset","length","key_hex"])
            w.writeheader(); w.writerows(rows)
        print(f"csv={args.csv}")
if __name__=="__main__":
    main()
