#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

HEXLINE = re.compile(r"^[0-9a-fA-F]{8}\s+((?:[0-9a-fA-F]{2}[ -]?){1,16})")

DUMP_MARKERS = {
    "V20_1_VLH_SEEDBASE_AFTER_EBP_M54": ("vlh", "seedbase_after_80.bin"),
    "V20_1_NEWGENEX_OUTBUF_ENTRY_100": ("ksec_entry", "outbuf_entry_100.bin"),
    "V20_1_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100": ("ksec_after_gather", "outbuf_100.bin"),
    "V20_1_KSEC_NEWGENEX_OUTBUF_COMMON_POST_100": ("ksec_common_post", "outbuf_100.bin"),
    "V20_1_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100": ("ksec_pre_return", "outbuf_100.bin"),
    "V20_1_ADVAPI_IOCTL_OUTBUF_100": ("advapi_ioctl", "outbuf_100.bin"),
    "V20_1_ADVAPI_IOCTL_INBUF_100": ("advapi_ioctl", "inbuf_100.bin"),
}

EVENT_MARKERS = [
    "V20_1_VLH_EXIT_F7459724",
    "V20_1_NEWGENEX_ENTRY_F7459951",
    "V20_1_NEWGENEX_AFTER_GATHER_F74599A6",
    "V20_1_NEWGENEX_COMMON_POST_F74599B5",
    "V20_1_NEWGENEX_PRE_RETURN_F74599C8",
    "V20_1_ADVAPI_IOCTL_AFTER_C2",
]

PRINTF_KV = re.compile(r"([A-Za-z0-9_]+)=([0-9a-fA-F]+)")

def collect_dump(lines, start):
    data = []
    i = start
    while i < len(lines):
        m = HEXLINE.match(lines[i].strip())
        if not m:
            break
        part = m.group(1).replace("-", " ")
        data.extend(x.lower() for x in part.split() if len(x) == 2)
        i += 1
    return bytes.fromhex("".join(data)), i

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--samples")
    ap.add_argument("--jsonl")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    lines = Path(args.log).read_text(errors="replace").splitlines()
    events = []
    counts = {}
    current = None
    seq = {}

    samples = Path(args.samples) if args.samples else None
    if samples:
        samples.mkdir(parents=True, exist_ok=True)

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("[") and line.endswith("]"):
            marker = line.strip("[]")
            if marker in EVENT_MARKERS:
                current = {
                    "event_index": len(events) + 1,
                    "marker": marker,
                    "line": i + 1,
                }
                events.append(current)
                counts[marker] = counts.get(marker, 0) + 1
            elif marker in DUMP_MARKERS:
                kind, filename = DUMP_MARKERS[marker]
                data, ni = collect_dump(lines, i + 1)
                counts[marker] = counts.get(marker, 0) + 1

                if current is not None:
                    current.setdefault("dumps", {})[marker] = {
                        "length": len(data),
                        "sha256": __import__("hashlib").sha256(data).hexdigest(),
                        "head16": data[:16].hex(),
                    }

                if samples and data:
                    seq[kind] = seq.get(kind, 0) + 1
                    outdir = samples / f"{kind}_{seq[kind]:02d}"
                    outdir.mkdir(parents=True, exist_ok=True)
                    (outdir / filename).write_bytes(data)
                    meta = {
                        "marker": marker,
                        "line": i + 1,
                        "length": len(data),
                        "head16": data[:16].hex(),
                        "sha256": __import__("hashlib").sha256(data).hexdigest(),
                    }
                    (outdir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

                i = ni
                continue

        if current is not None and "=" in line:
            for k, v in PRINTF_KV.findall(line):
                current[k] = v.lower()

        i += 1

    if args.jsonl:
        with open(args.jsonl, "w") as f:
            for e in events:
                f.write(json.dumps(e, sort_keys=True) + "\n")

    print("[SEED2STATE V20.1 PRECISE NEWGENRANDOMEX OUTBUF REPORT]")
    print(f"file={args.log}")
    print()
    print("[COUNTS]")
    for k in sorted(counts):
        print(f"{k:48s} {counts[k]}")
    print()
    print("[EVENTS]")
    for e in events:
        print(f"#{e['event_index']} {e['marker']} line={e['line']}")
        if "arg_outbuf" in e:
            print(f"  arg_outbuf={e.get('arg_outbuf')} arg_len_value={e.get('arg_len_value')} eax={e.get('eax')}")
        if "ioctl_outbuf" in e:
            print(f"  ioctl_outbuf={e.get('ioctl_outbuf')} outlen={e.get('ioctl_outlen')} inbuf={e.get('ioctl_inbuf')}")
        for m, d in e.get("dumps", {}).items():
            print(f"  dump {m}: len={d['length']} head16={d['head16']} sha256={d['sha256']}")
    print()
    if samples:
        print(f"[SAMPLES] wrote={samples}")

if __name__ == "__main__":
    main()
