#!/usr/bin/env python3
import argparse, json, re
from pathlib import Path
from collections import Counter

MAIN={
"V18_1_MANUAL_VLH_EXIT_F7459724",
"V18_1_MANUAL_KSEC_LATE_F74599A6",
"V18_1_ADVAPI_IOCTL_AFTER_C2",
"V18_1_SYSTEMFUNCTION036_ENTRY",
"V18_1_SYSTEMFUNCTION036_RETURN",
"V18_1_RC4_PRGA_ENTRY",
"V18_1_RC4_PRGA_RETURN",
}
MARK=re.compile(r"^\[(V18_1_[A-Z0-9_]+|SEED2STATE_V18_1_[A-Z0-9_]+)\]")
ADDR=re.compile(r"^\s*([0-9a-fA-F]{8})\s+(.*)$")
HEX2=re.compile(r"^[0-9a-fA-F]{2}$")

def clean(tok):
    if "-" in tok:
        return [p.lower() for p in tok.split("-") if HEX2.match(p)]
    return [tok.lower()] if HEX2.match(tok) else []

def parse_db(lines,i):
    data=bytearray(); j=i+1
    while j<len(lines):
        line=lines[j]
        if MARK.match(line): break
        m=ADDR.match(line)
        if not m:
            if any(x in line for x in ["eax=","ret=","proc=","ioctl_","kernel_outbuf","# ChildEBP"]): break
            j+=1; continue
        for tok in m.group(2).split():
            if not re.fullmatch(r"[0-9a-fA-F-]{2,5}",tok): break
            for b in clean(tok): data.append(int(b,16))
        j+=1
    return bytes(data),j

def kv(line):
    return {k:v.lower() for k,v in re.findall(r"([A-Za-z0-9_]+)=([0-9a-fA-F]+)",line)}

class Event:
    def __init__(self,kind,line):
        self.kind=kind; self.line=line; self.kv={}; self.blocks={}

def parse_events(path):
    lines=Path(path).read_text(errors="replace").splitlines()
    evs=[]; active=None; i=0
    while i<len(lines):
        m=MARK.match(lines[i])
        if m:
            name=m.group(1)
            if name in MAIN:
                active=Event(name,i+1); evs.append(active); i+=1; continue
            if name.startswith("V18_1_") and active:
                data,ni=parse_db(lines,i)
                if data: active.blocks[name]=data
                i=ni; continue
        if active:
            d=kv(lines[i])
            if d: active.kv.update(d)
        i+=1
    return evs

def block(e,n,limit=None):
    if not e or n not in e.blocks: return None
    b=e.blocks[n]
    return b[:limit] if limit else b

def hx(b): return b.hex() if b is not None else None

def pair_seq(evs,a,b):
    pairs=[]; p=None
    for e in evs:
        if e.kind==a:
            p=e
        elif e.kind==b and p:
            pairs.append((p,e)); p=None
    return pairs

def is_perm256(b):
    return len(b)>=256 and sorted(b[:256])==list(range(256))

def output_matches(e,outs):
    ms=[]
    for name,b in e.blocks.items():
        for idx,o in outs:
            if o:
                pos=b.find(o)
                if pos>=0: ms.append({"sysfunc":idx,"block":name,"pos":pos})
    return ms

def find_positions(buf, needle):
    out=[]; start=0
    if not buf or not needle: return out
    while True:
        pos=buf.find(needle,start)
        if pos<0: break
        out.append(pos); start=pos+1
    return out

def ksa(key):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff
        S[i],S[j]=S[j],S[i]
    return bytes(S)

def write_bytes(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(b or b"")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--jsonl")
    ap.add_argument("--samples")
    args=ap.parse_args()

    evs=parse_events(args.log)
    counts=Counter(e.kind for e in evs)
    vlhs=[e for e in evs if e.kind=="V18_1_MANUAL_VLH_EXIT_F7459724"]
    ksecs=[e for e in evs if e.kind=="V18_1_MANUAL_KSEC_LATE_F74599A6"]
    ioctls=[e for e in evs if e.kind=="V18_1_ADVAPI_IOCTL_AFTER_C2"]
    sysrets=[e for e in evs if e.kind=="V18_1_SYSTEMFUNCTION036_RETURN"]
    outs=[(i,block(e,"V18_1_SYSFUNC_OUT_AFTER",20)) for i,e in enumerate(sysrets,1)]
    prgas=pair_seq(evs,"V18_1_RC4_PRGA_ENTRY","V18_1_RC4_PRGA_RETURN")

    print("[SEED2STATE V18.1 KSECDD KERNEL OUTBUF MANUAL REPORT]")
    print(f"file={args.log}\n")

    print("[COUNTS]")
    for k in sorted(counts): print(f"{k:42s} {counts[k]}")
    print()

    print("[VLH SEEDBASE_AFTER]")
    for i,e in enumerate(vlhs,1):
        b=block(e,"V18_1_MANUAL_VLH_SEEDBASE_AFTER_EBP_M54",80)
        print(f"VLH#{i} line={e.line} seedbase80={hx(b)}")
    print()

    print("[KSECDD KERNEL OUTBUF]")
    ksec_bufs=[]
    for i,e in enumerate(ksecs,1):
        b=block(e,"V18_1_MANUAL_KSEC_KERNEL_OUTBUF_100",256)
        if b: ksec_bufs.append((i,b,e))
        print(f"KSEC#{i} line={e.line} kernel_outbuf={e.kv.get('kernel_outbuf')} len={e.kv.get('len')} dump_len={len(b) if b else 0} head16={hx(b[:16]) if b else None}")
    print()

    print("[ADVAPI IOCTL OUTBUFS]")
    ioctl_bufs=[]
    for i,e in enumerate(ioctls,1):
        b=block(e,"V18_1_IOCTL_OUTBUF_100",256)
        if b: ioctl_bufs.append((i,b,e))
        print(f"IOCTL#{i} line={e.line} outbuf={e.kv.get('ioctl_outbuf')} outlen={e.kv.get('ioctl_outlen')} dump_len={len(b) if b else 0} head16={hx(b[:16]) if b else None}")
    print()

    print("[KSECDD -> ADVAPI IOCTL MATCHES]")
    ksec_ioctl_matches=[]
    for ki,kb,ke in ksec_bufs:
        for ii,ib,ie in ioctl_bufs:
            if kb == ib:
                row={"ksec":ki,"ioctl":ii,"kind":"exact_256"}
                ksec_ioctl_matches.append(row)
                print(f"MATCH exact KSEC#{ki} == IOCTL#{ii}")
            else:
                pos=find_positions(kb,ib)
                for p in pos:
                    row={"ksec":ki,"ioctl":ii,"kind":"ioctl_inside_ksec","offset":p}
                    ksec_ioctl_matches.append(row)
                    print(f"MATCH IOCTL#{ii} inside KSEC#{ki} offset={p}")
                pos2=find_positions(ib,kb)
                for p in pos2:
                    row={"ksec":ki,"ioctl":ii,"kind":"ksec_inside_ioctl","offset":p}
                    ksec_ioctl_matches.append(row)
                    print(f"MATCH KSEC#{ki} inside IOCTL#{ii} offset={p}")
    print(f"ksec_kernel_to_ioctl_exact_matches={sum(1 for r in ksec_ioctl_matches if r['kind']=='exact_256')}")
    print(f"ksec_kernel_to_ioctl_total_matches={len(ksec_ioctl_matches)}\n")

    print("[SYSTEMFUNCTION036 OUT20]")
    for i,o in outs:
        print(f"#{i} {hx(o)}")
    print()

    print("[PRGA CALLS]")
    prga_records=[]
    for i,(en,ret) in enumerate(prgas,1):
        sb=block(en,"V18_1_PRGA_STATE_BEFORE_SIJ",258)
        sa=block(ret,"V18_1_PRGA_STATE_AFTER_SIJ",258)
        ms=output_matches(ret,outs)
        rec={
            "index":i,
            "entry_line":en.line,
            "return_line":ret.line,
            "s_ptr":en.kv.get("s_ptr"),
            "length":en.kv.get("len"),
            "out_ptr":en.kv.get("out_ptr"),
            "i_before":sb[256] if sb and len(sb)>=258 else None,
            "j_before":sb[257] if sb and len(sb)>=258 else None,
            "i_after":sa[256] if sa and len(sa)>=258 else None,
            "j_after":sa[257] if sa and len(sa)>=258 else None,
            "perm_before":bool(sb and is_perm256(sb)),
            "perm_after":bool(sa and is_perm256(sa)),
            "output_matches":ms,
        }
        prga_records.append(rec)
        print(f"PRGA#{i:02d} s_ptr={rec['s_ptr']} len={rec['length']} i/j={rec['i_before']}/{rec['j_before']}->{rec['i_after']}/{rec['j_after']} matches={len(ms)}")
    print()

    print("[ADVAPI IOCTL -> RC4 KSA MATCHES]")
    ksa_rows=[]
    for rec,(en,ret) in zip(prga_records,prgas):
        sb=block(en,"V18_1_PRGA_STATE_BEFORE_SIJ",258)
        if not sb: continue
        S=sb[:256]
        for ii,ib,ie in ioctl_bufs:
            if len(ib)>=256 and ksa(ib[:256])==S:
                ksa_rows.append({"state":rec["index"],"ioctl":ii,"i":rec["i_before"],"j":rec["j_before"]})
                print(f"MATCH IOCTL#{ii} -> PRGA#{rec['index']:02d} i={rec['i_before']:02x} j={rec['j_before']:02x}")
    print(f"ioctl_to_rc4_ksa_matches={len(ksa_rows)}\n")

    if args.samples:
        root=Path(args.samples); root.mkdir(parents=True,exist_ok=True)
        for i,e in enumerate(vlhs,1):
            d=root/f"vlh_{i:02d}"; d.mkdir(parents=True,exist_ok=True)
            for n,b in e.blocks.items(): write_bytes(d/(n+".bin"),b)
        for i,e in enumerate(ksecs,1):
            d=root/f"ksec_{i:02d}"; d.mkdir(parents=True,exist_ok=True)
            for n,b in e.blocks.items(): write_bytes(d/(n+".bin"),b)
            (d/"meta.json").write_text(json.dumps(e.kv,indent=2,sort_keys=True),encoding="utf-8")
        for i,e in enumerate(ioctls,1):
            d=root/f"ioctl_{i:02d}"; d.mkdir(parents=True,exist_ok=True)
            for n,b in e.blocks.items():
                if n.startswith("V18_1_IOCTL_"):
                    write_bytes(d/(n+".bin"),b)
            meta={k:e.kv.get(k) for k in ["ioctl_outbuf","ioctl_outlen","bytesret_ptr","ioctl_inbuf","ioctl_inlen"]}
            (d/"meta.json").write_text(json.dumps(meta,indent=2,sort_keys=True),encoding="utf-8")
        for i,(en,ret) in enumerate(prgas,1):
            d=root/f"prga_{i:03d}"; d.mkdir(parents=True,exist_ok=True)
            files={
                "state_before_sij.bin":block(en,"V18_1_PRGA_STATE_BEFORE_SIJ",258),
                "state_after_sij.bin":block(ret,"V18_1_PRGA_STATE_AFTER_SIJ",258),
                "output_before.bin":block(en,"V18_1_PRGA_OUTPUT_BEFORE",40),
                "output_after.bin":block(ret,"V18_1_PRGA_OUTPUT_AFTER",40),
            }
            for fn,b in files.items(): write_bytes(d/fn,b)
            (d/"meta.json").write_text(json.dumps(prga_records[i-1],indent=2,sort_keys=True),encoding="utf-8")
        (root/"ksec_ioctl_matches.json").write_text(json.dumps(ksec_ioctl_matches,indent=2,sort_keys=True),encoding="utf-8")
        (root/"ioctl_ksa_matches.json").write_text(json.dumps(ksa_rows,indent=2,sort_keys=True),encoding="utf-8")
        print(f"[SAMPLES]\nwrote={root}\n")

    print("[DIAGNOSTICS]")
    if ksec_bufs: print("- KSecDD kernel_outbuf[0x100] was captured.")
    else: print("- No KSecDD kernel_outbuf[0x100] parsed.")
    if ioctl_bufs: print("- ADVAPI IOCTL outbuf[0x100] was captured.")
    if ksec_ioctl_matches: print("- KSecDD kernel buffer matches at least one ADVAPI IOCTL buffer.")
    else: print("- No KSecDD/ADVAPI exact buffer match found in parsed data.")
    if ksa_rows: print("- ADVAPI IOCTL to RC4 KSA relation was observed.")
    if any(r["output_matches"] for r in prga_records): print("- PRGA outputs match SystemFunction036 outputs.")

    if args.jsonl:
        with open(args.jsonl,"w") as f:
            for r in ksec_ioctl_matches:
                f.write(json.dumps({"type":"ksec_ioctl_match",**r},sort_keys=True)+"\n")
            for r in ksa_rows:
                f.write(json.dumps({"type":"ioctl_ksa_match",**r},sort_keys=True)+"\n")
            for r in prga_records:
                f.write(json.dumps({"type":"prga",**r},sort_keys=True)+"\n")
        print(f"\n[JSONL]\nwrote={args.jsonl}")

if __name__=="__main__":
    main()
