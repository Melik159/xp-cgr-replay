#!/usr/bin/env python3
import argparse,json
from pathlib import Path

def rc4_xor(state, ob, n):
    S=list(state[:256]); i=state[256]; j=state[257]
    out=bytearray(ob[:n])
    for k in range(n):
        i=(i+1)&0xff; j=(j+S[i])&0xff
        S[i],S[j]=S[j],S[i]
        out[k]^=S[(S[i]+S[j])&0xff]
    return bytes(out), bytes(S)+bytes([i,j])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("samples_dir")
    args=ap.parse_args()
    ok=0; total=0
    for d in sorted(Path(args.samples_dir).glob("prga_*")):
        meta=json.loads((d/"meta.json").read_text())
        if meta.get("length")!="00000014": continue
        sb=(d/"state_before_sij.bin").read_bytes()
        sa=(d/"state_after_sij.bin").read_bytes()
        ob=(d/"output_before.bin").read_bytes()
        oa=(d/"output_after.bin").read_bytes()
        comp,state=rc4_xor(sb,ob,20)
        out_match=comp==oa[:20]
        state_match=state==sa[:258]
        total+=1
        if out_match and state_match: ok+=1
        print(f"{d.name}: output_match={out_match} state_match={state_match}")
    print(f"[SUMMARY] useful_prga_replay_ok={ok}/{total}")
if __name__=="__main__":
    main()
