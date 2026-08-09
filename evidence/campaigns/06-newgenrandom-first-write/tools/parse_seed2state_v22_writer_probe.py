#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path
from collections import Counter

MARKER_RE = re.compile(r"^\[([A-Z0-9_]+)\]")
REG_RE = re.compile(r"\b([a-z]{2,3})=([0-9a-fA-F]{8})\b")
EXPR_RE = re.compile(r"Evaluate expression:\s+(-?[0-9]+)\s*=\s*([0-9a-fA-F`]+)")
DUMP_ADDR_RE = re.compile(r"^\s*[0-9a-fA-F`]{8,16}\s+(.*)$")

EVENTS = {
    "V22_WRITER_NEWGENEX_ENTRY_F7459951",
    "V22_WRITER_VLH_CHECKPOINT_F7459724",
    "V22_WRITER_OUTBUF_FIRST_WRITE",
    "V22_WRITER_NEWGENEX_AFTER_GATHER_F74599A6",
    "V22_WRITER_NEWGENEX_PRE_RETURN_F74599C8",
    "V22_WRITER_ADVAPI_IOCTL_AFTER_C2",
    "V22_1_ADVAPI_IOCTL_AFTER_C2",
}

DUMPS = {
    "V22_WRITER_NEWGENEX_OUTBUF_ENTRY_100": ("ksec_entry", "outbuf_entry_100.bin"),
    "V22_WRITER_OUTBUF_AT_FIRST_WRITE_100": ("writer", "outbuf_at_first_write_100.bin"),
    "V22_WRITER_OUTBUF_AROUND_FIRST_WRITE_180": ("writer", "outbuf_around_first_write_180.bin"),

    "V22_WRITER_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100": ("ksec_after_gather", "outbuf_100.bin"),
    "V22_WRITER_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100": ("ksec_pre_return", "outbuf_100.bin"),

    "V22_WRITER_ADVAPI_IOCTL_OUTBUF_100": ("advapi_ioctl", "outbuf_100.bin"),
    "V22_WRITER_ADVAPI_IOCTL_INBUF_100": ("advapi_ioctl", "inbuf_100.bin"),

    "V22_1_ADVAPI_IOCTL_OUTBUF_100": ("advapi_ioctl", "outbuf_100.bin"),
    "V22_1_ADVAPI_IOCTL_INBUF_100": ("advapi_ioctl", "inbuf_100.bin"),

    "V22_WRITER_VLH_SEEDBASE_AFTER_EBP_M54": ("vlh", "seedbase_after_80.bin"),
}

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def bytes_from_db_line(line: str) -> bytes:
    m = DUMP_ADDR_RE.match(line)
    if not m:
        return b""

    rest = m.group(1).replace("-", " ")
    out = bytearray()

    for tok in rest.split():
        if re.fullmatch(r"[0-9a-fA-F]{2}", tok):
            out.append(int(tok, 16))
        elif re.fullmatch(r"\?\?", tok):
            continue

    return bytes(out)

def parse_dump(lines, i):
    data = bytearray()
    started = False

    while i < len(lines):
        line = lines[i].rstrip("\n")

        if MARKER_RE.match(line.strip()):
            break

        b = bytes_from_db_line(line)
        if b:
            started = True
            data.extend(b)
            i += 1
            continue

        if started:
            break

        i += 1

    return bytes(data), i

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--samples")
    ap.add_argument("--jsonl")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    lines = Path(args.log).read_text(errors="replace").splitlines()

    sample_root = Path(args.samples) if args.samples else None
    if sample_root:
        sample_root.mkdir(parents=True, exist_ok=True)

    events = []
    counts = Counter()
    sample_counts = Counter()

    cur = None
    last_marker = None
    i = 0

    while i < len(lines):
        line = lines[i]
        mm = MARKER_RE.match(line.strip())

        if mm:
            marker = mm.group(1)
            counts[marker] += 1
            last_marker = marker

            if marker in EVENTS:
                cur = {
                    "event_index": len(events) + 1,
                    "marker": marker,
                    "line": i + 1,
                    "kv": {},
                    "dumps": {},
                }
                events.append(cur)

            elif marker in DUMPS:
                data, j = parse_dump(lines, i + 1)
                kind, filename = DUMPS[marker]

                info = {
                    "kind": kind,
                    "len": len(data),
                    "head16": data[:16].hex(),
                    "sha256": sha256(data),
                }

                if sample_root:
                    sample_counts[kind] += 1
                    d = sample_root / f"{kind}_{sample_counts[kind]:02d}"
                    d.mkdir(parents=True, exist_ok=True)

                    out = d / filename
                    out.write_bytes(data)

                    meta = {
                        "marker": marker,
                        "line": i + 1,
                        **info,
                    }
                    (d / "meta.json").write_text(
                        json.dumps(meta, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )

                    info.update({
                        "sample": str(out),
                        "sample_index": sample_counts[kind],
                        "filename": filename,
                    })

                if cur is not None:
                    cur["dumps"][marker] = info

                i = j
                continue

        if cur is not None:
            for k, v in REG_RE.findall(line):
                cur["kv"][k] = v.lower()

            if "KSecDD!rc4+0xfb" in line:
                cur["kv"]["symbol_hint"] = line.strip()

            em = EXPR_RE.search(line)
            if em and last_marker:
                cur["kv"][last_marker.lower()] = em.group(2).lower().replace("`", "")

        i += 1

    print("[SEED2STATE V22 WRITER PROBE REPORT]")
    print(f"file={args.log}")
    print()
    print("[COUNTS]")
    for k, v in sorted(counts.items()):
        print(f"{k:60s} {v}")

    if args.pretty:
        print()
        print("[EVENTS]")
        for ev in events:
            print(f"#{ev['event_index']} {ev['marker']} line={ev['line']}")
            if ev["kv"]:
                print("  kv=" + json.dumps(ev["kv"], sort_keys=True))
            for name, d in ev["dumps"].items():
                print(
                    f"  dump {name}: "
                    f"len={d['len']} "
                    f"head16={d['head16']} "
                    f"sha256={d['sha256']}"
                )

    if args.jsonl:
        out = Path(args.jsonl)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, sort_keys=True) + "\n")

if __name__ == "__main__":
    main()
