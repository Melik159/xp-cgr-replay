#!/usr/bin/env python3
from pathlib import Path
import csv
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'plots'; OUT.mkdir(exist_ok=True)

def rows(name):
    with (ROOT/'data'/name).open(encoding='utf-8') as f:return list(csv.DictReader(f))

r=rows('optimization_history.csv'); labels=[x['stage'] for x in r]; vals=[float(x['rate_m_candidates_s']) for x in r]
fig,ax=plt.subplots(figsize=(10,5));ax.bar(labels,vals);ax.set_ylabel('Million candidates/s');ax.set_title('Tesla P100 – CUDA optimization progression');ax.tick_params(axis='x',rotation=30);fig.tight_layout();fig.savefig(OUT/'optimization_progression.png',dpi=180);plt.close(fig)
r=rows('register_sweep.csv');x=[int(v['max_registers']) for v in r];y=[float(v['rate_m_candidates_s']) for v in r]
fig,ax=plt.subplots(figsize=(8,5));ax.plot(x,y,marker='o');ax.set_xlabel('Max registers/thread');ax.set_ylabel('Million candidates/s');ax.set_title('Register-pressure sweep');fig.tight_layout();fig.savefig(OUT/'register_sweep.png',dpi=180);plt.close(fig)
r=rows('padding_sweep.csv');x=[f"PAD {v['pad_bytes']}\n{v['blocks_per_sm']} blocks/SM" for v in r];y=[float(v['rate_m_candidates_s']) for v in r]
fig,ax=plt.subplots(figsize=(9,5));ax.bar(x,y);ax.set_ylabel('Million candidates/s');ax.set_title('Shared-memory padding sweep');fig.tight_layout();fig.savefig(OUT/'padding_sweep.png',dpi=180);plt.close(fig)
print(f'PLOTS PASS out={OUT}')
