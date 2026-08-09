#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path

MARKER_RE = re.compile(r'^\[([^\]]+)\]')
REG_RE = re.compile(r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|eip|efl|peb|teb)=([0-9a-fA-F]{8})\b')
EVAL_RE = re.compile(r'Evaluate expression:\s*(-?\d+)\s*=\s*([0-9a-fA-F`]+)')
DB_RE = re.compile(r'^\s*[0-9a-fA-F`]{8,16}\s+((?:[0-9a-fA-F]{2}(?:[\s-]+|$)){1,16})')

DUMP_MARKER_PARTS = (
    'OUTBUF', 'INBUF', 'STATE_', 'STATE_BEFORE', 'STATE_ENTRY', 'STATE_RETURN',
    'KEYBUF', 'STRUCT', 'REGION', 'SEEDBASE'
)


def is_dump_marker(marker: str) -> bool:
    return any(part in marker for part in DUMP_MARKER_PARTS)


def parse_db_line(line: str):
    m = DB_RE.match(line)
    if not m:
        return None
    return bytes(int(x, 16) for x in re.findall(r'[0-9a-fA-F]{2}', m.group(1))[:16])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('--samples', required=True)
    ap.add_argument('--jsonl', required=True)
    ap.add_argument('--pretty', action='store_true')
    args = ap.parse_args()

    sample_dir = Path(args.samples)
    sample_dir.mkdir(parents=True, exist_ok=True)
    events = []
    current = None

    lines = Path(args.log).read_text(errors='replace').splitlines()
    for lineno, line in enumerate(lines, 1):
        mm = MARKER_RE.match(line)
        if mm:
            marker = mm.group(1)
            current = {
                'line': lineno,
                'marker': marker,
                'regs': {},
                'eval': None,
                'dump': None,
                'raw': [] if args.pretty else None,
            }
            events.append(current)
            continue

        if current is None:
            continue

        if args.pretty and len(current['raw']) < 80:
            current['raw'].append(line)

        for reg, val in REG_RE.findall(line):
            current['regs'][reg.lower()] = val.lower()

        em = EVAL_RE.search(line)
        if em:
            try:
                dec = int(em.group(1))
            except ValueError:
                dec = None
            current['eval'] = {'dec': dec, 'hex': em.group(2).replace('`', '').lower()}

        if is_dump_marker(current['marker']):
            b = parse_db_line(line)
            if b is not None:
                if current['dump'] is None:
                    current['dump'] = bytearray()
                current['dump'].extend(b)

    # finalize dumps and write samples
    counters = {}
    for ev in events:
        if isinstance(ev.get('dump'), bytearray):
            data = bytes(ev['dump'])
            marker = ev['marker']
            counters[marker] = counters.get(marker, 0) + 1
            idx = counters[marker]
            name = f'{idx:03d}_{marker}.bin'
            path = sample_dir / name
            path.write_bytes(data)
            ev['dump'] = {
                'file': str(path),
                'len': len(data),
                'head16': data[:16].hex(),
                'sha256': hashlib.sha256(data).hexdigest(),
            }

    Path(args.jsonl).parent.mkdir(parents=True, exist_ok=True)
    with open(args.jsonl, 'w', encoding='utf-8') as f:
        for ev in events:
            f.write(json.dumps(ev, sort_keys=True) + '\n')

    print('[SEED2STATE V24 CLOSE-G PARSE REPORT]')
    print(f'file={args.log}')
    print('\n[COUNTS]')
    counts = {}
    for ev in events:
        counts[ev['marker']] = counts.get(ev['marker'], 0) + 1
    for k in sorted(counts):
        print(f'{k:60s} {counts[k]}')
    print(f'\n[SAMPLES] wrote={args.samples}')
    print(f'[JSONL] wrote={args.jsonl}')


if __name__ == '__main__':
    main()
