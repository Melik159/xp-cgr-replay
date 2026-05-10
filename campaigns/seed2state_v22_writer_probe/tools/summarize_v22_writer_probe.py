#!/usr/bin/env python3
import argparse, json
from collections import Counter
ap=argparse.ArgumentParser()
ap.add_argument("jsonl")
args=ap.parse_args()
events=[json.loads(l) for l in open(args.jsonl)]
writers=[e for e in events if e["marker"]=="V22_WRITER_OUTBUF_FIRST_WRITE"]
print(f"writers={len(writers)}")
c=Counter((e.get("kv",{}).get("symbol_hint") or e.get("kv",{}).get("eip") or "-") for e in writers)
for k,v in c.most_common():
    print(f"{v:4d} {k}")
for i,e in enumerate(writers,1):
    d=e.get("dumps",{}).get("V22_WRITER_OUTBUF_AT_FIRST_WRITE_100",{})
    print(f"writer#{i} line={e.get('line')} head16={d.get('head16')} sha256={d.get('sha256')}")
