#!/usr/bin/env python3
import argparse, json, re
from pathlib import Path
from collections import Counter

MAIN={
"V17_1_ADVAPI_IOCTL_AFTER_C2",
"V17_1_SYSTEMFUNCTION036_ENTRY",
"V17_1_SYSTEMFUNCTION036_RETURN",
"V17_1_RC4_SELECT_ENTRY",
"V17_1_RC4_SELECT_RETURN",
"V17_1_RC4_SAFE_ENTRY",
"V17_1_RC4_PRGA_ENTRY",
"V17_1_RC4_PRGA_RETURN",
}
MARK=re.compile(r"^\[(V17_1_[A-Z0-9_]+|SEED2STATE_V17_1_[A-Z0-9_]+)\]")
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
            if any(x in line for x in ["eax=","ret=","proc=","ioctl_","# ChildEBP"]): break
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
            if name.startswith("V17_1_") and active:
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
def is_perm256(b): return len(b)>=256 and sorted(b[:256])==list(range(256))
def pair_seq(evs,a,b):
    pairs=[]; p=None
    for e in evs:
        if e.kind==a: p=e
        elif e.kind==b and p:
            pairs.append((p,e)); p=None
    return pairs
def exec_id(e):
    return f"proc={e.kv.get('proc')}/thread={e.kv.get('thread')}/peb={e.kv.get('peb')}/teb={e.kv.get('teb')}"

def output_matches(e,outs):
    ms=[]
    for name,b in e.blocks.items():
        for idx,o in outs:
            if o:
                pos=b.find(o)
                if pos>=0: ms.append({"sysfunc":idx,"block":name,"pos":pos})
    return ms

def write_bytes(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(b or b"")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--pretty",action="store_true")
    ap.add_argument("--jsonl")
    ap.add_argument("--samples")
    args=ap.parse_args()

    evs=parse_events(args.log)
    counts=Counter(e.kind for e in evs)
    ioctls=[e for e in evs if e.kind=="V17_1_ADVAPI_IOCTL_AFTER_C2"]
    sysrets=[e for e in evs if e.kind=="V17_1_SYSTEMFUNCTION036_RETURN"]
    outs=[(i,block(e,"V17_1_SYSFUNC_OUT_AFTER",20)) for i,e in enumerate(sysrets,1)]
    prgas=pair_seq(evs,"V17_1_RC4_PRGA_ENTRY","V17_1_RC4_PRGA_RETURN")
    records=[]

    print("[SEED2STATE V17.1 PRECISE IOCTL OUTBUF REPORT]")
    print(f"file={args.log}\n")
    print("[COUNTS]")
    for k in sorted(counts): print(f"{k:42s} {counts[k]}")
    print()

    print("[IOCTL OUTBUFS]")
    outbuf_count=0
    for i,e in enumerate(ioctls,1):
        outbuf=block(e,"V17_1_IOCTL_OUTBUF_100")
        inbuf=block(e,"V17_1_IOCTL_INBUF_100")
        if outbuf: outbuf_count += 1
        print(f"IOCTL#{i} line={e.line} outbuf_ptr={e.kv.get('ioctl_outbuf')} outlen={e.kv.get('ioctl_outlen')} bytesret={e.kv.get('bytesret_ptr')}")
        print(f"  outbuf_len={len(outbuf) if outbuf else 0} outbuf_head16={hx(outbuf[:16]) if outbuf else None}")
        print(f"  inbuf_len={len(inbuf) if inbuf else 0} inbuf_head16={hx(inbuf[:16]) if inbuf else None}")
    print(f"ioctl_outbufs={outbuf_count}\n")

    print("[SYSTEMFUNCTION036 OUT20]")
    for i,o in outs: print(f"#{i} {hx(o)}")
    print()

    print("[PRGA CALLS]")
    for i,(en,ret) in enumerate(prgas,1):
        sb=block(en,"V17_1_PRGA_STATE_BEFORE_SIJ",258)
        sa=block(ret,"V17_1_PRGA_STATE_AFTER_SIJ",258)
        ms=output_matches(ret,outs)
        rec={
            "index":i,
            "entry_line":en.line,
            "return_line":ret.line,
            "s_ptr":en.kv.get("arg04_s_ptr"),
            "length":en.kv.get("arg08_len"),
            "out_ptr":en.kv.get("arg0c_out"),
            "i_before": sb[256] if sb and len(sb)>=258 else None,
            "j_before": sb[257] if sb and len(sb)>=258 else None,
            "i_after": sa[256] if sa and len(sa)>=258 else None,
            "j_after": sa[257] if sa and len(sa)>=258 else None,
            "state_before_perm": bool(sb and is_perm256(sb)),
            "state_after_perm": bool(sa and is_perm256(sa)),
            "output_matches": ms,
        }
        records.append(rec)
        print(f"PRGA#{i:02d} s_ptr={rec['s_ptr']} len={rec['length']} i/j={rec['i_before']}/{rec['j_before']}->{rec['i_after']}/{rec['j_after']} matches={len(ms)}")
        for m in ms:
            print(f"  output_match sysfunc#{m['sysfunc']} block={m['block']} pos={m['pos']}")
    print()

    if args.samples:
        root=Path(args.samples); root.mkdir(parents=True,exist_ok=True)
        for i,e in enumerate(ioctls,1):
            d=root/f"ioctl_{i:02d}"; d.mkdir(parents=True,exist_ok=True)
            for n in ["V17_1_IOCTL_OUTBUF_100","V17_1_IOCTL_INBUF_100","V17_1_IOCTL_STACK_DD_ESP_M20"]:
                write_bytes(d/(n+".bin"), block(e,n))
            meta={k:e.kv.get(k) for k in ["ioctl_outbuf","ioctl_outlen","bytesret_ptr","ioctl_inbuf","ioctl_inlen","proc","thread","peb","teb"]}
            (d/"meta.json").write_text(json.dumps(meta,indent=2,sort_keys=True),encoding="utf-8")
        sj=[]
        for i,(en,ret) in enumerate(prgas,1):
            d=root/f"prga_{i:03d}"; d.mkdir(parents=True,exist_ok=True)
            files={
                "state_before_sij.bin":block(en,"V17_1_PRGA_STATE_BEFORE_SIJ",258),
                "state_after_sij.bin":block(ret,"V17_1_PRGA_STATE_AFTER_SIJ",258),
                "output_before.bin":block(en,"V17_1_PRGA_OUTPUT_BEFORE",40),
                "output_after.bin":block(ret,"V17_1_PRGA_OUTPUT_AFTER",40),
                "slot_before_120.bin":block(en,"V17_1_PRGA_SLOT_BEFORE_BASE_M04",0x120),
                "slot_after_120.bin":block(ret,"V17_1_PRGA_SLOT_AFTER_BASE_M04",0x120),
            }
            for fn,b in files.items(): write_bytes(d/fn,b)
            (d/"meta.json").write_text(json.dumps(records[i-1],indent=2,sort_keys=True),encoding="utf-8")
            sj.append(records[i-1])
        (root/"samples.jsonl").write_text("\n".join(json.dumps(r,sort_keys=True) for r in sj)+"\n",encoding="utf-8")
        print(f"[SAMPLES]\nwrote={root}\n")

    print("[DIAGNOSTICS]")
    if outbuf_count: print("- Precise IOCTL outbuf dumps were captured.")
    else: print("- No precise IOCTL outbuf dump parsed; inspect WinDbg memory access errors.")
    if any(r["output_matches"] for r in records): print("- PRGA outputs match SystemFunction036 outputs.")
    print("- Run replay_prga_useful_only.py, then scan_ioctl_outbuf_to_rc4_ksa.py.")

    if args.jsonl:
        with open(args.jsonl,"w") as f:
            for r in records: f.write(json.dumps(r,sort_keys=True)+"\n")
        print(f"\n[JSONL]\nwrote={args.jsonl}")

if __name__=="__main__":
    main()
