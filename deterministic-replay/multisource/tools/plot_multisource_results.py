#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv
from collections import defaultdict
from pathlib import Path
import matplotlib.pyplot as plt


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--results',type=Path,required=True); ap.add_argument('--out-dir',type=Path,required=True); a=ap.parse_args()
    rows=list(csv.DictReader(a.results.open(encoding='utf-8'))); a.out_dir.mkdir(parents=True,exist_ok=True)
    sources=sorted({r['source'] for r in rows}); events=sorted({int(r['event']) for r in rows})
    matrix=[]
    for s in sources:
        line=[]
        for e in events:
            subset=[r for r in rows if r['source']==s and int(r['event'])==e]
            line.append(sum(r['status']=='PASS' for r in subset)/len(subset) if subset else float('nan'))
        matrix.append(line)
    fig,ax=plt.subplots(figsize=(10,6)); im=ax.imshow(matrix,aspect='auto',vmin=0,vmax=1)
    ax.set_xticks(range(len(events)),[f'E{e}' for e in events]); ax.set_yticks(range(len(sources)),sources)
    ax.set_xlabel('KSec event'); ax.set_ylabel('Source'); ax.set_title('CUDA multisource validation – PASS fraction')
    fig.colorbar(im,ax=ax,label='PASS fraction'); fig.tight_layout(); fig.savefig(a.out_dir/'multisource_pass_matrix.png',dpi=180); plt.close(fig)
    rates=defaultdict(list)
    for r in rows:
        try: rates[r['source']].append(float(r['cuda_kernel_rate']))
        except ValueError: pass
    labels=sorted(rates); vals=[sum(rates[s])/len(rates[s]) for s in labels]
    fig,ax=plt.subplots(figsize=(10,5)); ax.bar(labels,vals); ax.set_ylabel('Candidates/s'); ax.set_title('CUDA correctness kernel – mean per-source rate'); ax.tick_params(axis='x',rotation=45); fig.tight_layout(); fig.savefig(a.out_dir/'multisource_rate_by_source.png',dpi=180); plt.close(fig)
    print(f'PLOTS PASS out={a.out_dir}')
if __name__=='__main__': main()
