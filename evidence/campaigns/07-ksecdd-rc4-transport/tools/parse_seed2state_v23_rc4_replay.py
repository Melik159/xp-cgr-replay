#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

MARKER_RE = re.compile(r"^\[([A-Za-z0-9_]+)\]\s*$")
ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=([0-9A-Fa-f`]+)\b")

EVENT_MARKERS = {
    "V23_RC4_NEWGENEX_ENTRY_F7459951",
    "V23_RC4_VLH_CHECKPOINT_F7459724",
    "V23_RC4_ENTRY_F745F010",
    "V23_RC4_OUTBUF_FIRST_WRITE",
    "V23_RC4_RETURN_F745F15A",
    "V23_RC4_NEWGENEX_AFTER_GATHER_F74599A6",
    "V23_RC4_NEWGENEX_PRE_RETURN_F74599C8",
    "V23_RC4_ADVAPI_IOCTL_AFTER_C2",
}

def safe_name(s):
    s = s.lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s)
    return s.strip("_")

def parse_assignments(line):
    out = {}
    for k, v in ASSIGN_RE.findall(line):
        out[k.lower()] = v.replace("`", "")
    return out

def parse_eval(line):
    # WinDbg style: Evaluate expression: 256 = 00000100
    if "Evaluate expression:" not in line:
        return None
    if "=" in line:
        return line.rsplit("=", 1)[-1].strip().replace("`", "")
    return line.split(":", 1)[-1].strip().replace("`", "")

def parse_dump_bytes(line):
    """
    Parse WinDbg db/dd-like byte rows:
    89f41b40  59 ca 1e 7a-f9 c2 ...
    Unknown bytes '??' are ignored by returning None for that row.
    """
    m = re.match(r"^\s*([0-9A-Fa-f`]{4,16})\s+(.+)$", line.rstrip())
    if not m:
        return None

    rest = m.group(2).strip()
    data = bytearray()

    for tok in rest.split():
        pieces = tok.split("-")
        if not pieces:
            break

        ok = True
        for p in pieces:
            if p == "??":
                return None
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", p):
                ok = False
                break

        if not ok:
            break

        for p in pieces:
            data.append(int(p, 16))

    return bytes(data) if data else None

def write_dump(samples_dir, ev, marker, data):
    ev_dir = samples_dir / f"{ev['event_index']:03d}_{safe_name(ev['marker'])}"
    ev_dir.mkdir(parents=True, exist_ok=True)

    base = safe_name(marker)
    filename = f"{base}.bin"
    path = ev_dir / filename

    # Avoid accidental overwrite if same marker appears twice under same event.
    n = 2
    while path.exists():
        filename = f"{base}_{n}.bin"
        path = ev_dir / filename
        n += 1

    path.write_bytes(data)

    rel = str(path)
    sha = hashlib.sha256(data).hexdigest()

    ev["dumps"][marker] = {
        "sample": rel,
        "filename": filename,
        "len": len(data),
        "head16": data[:16].hex(),
        "sha256": sha,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--samples", required=True)
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    log_path = Path(args.log)
    samples_dir = Path(args.samples)
    samples_dir.mkdir(parents=True, exist_ok=True)

    events = []
    marker_counts = Counter()

    current = None
    pending_marker = None
    pending_data = bytearray()

    def flush_pending():
        nonlocal pending_marker, pending_data, current
        if current is not None and pending_marker and pending_data:
            write_dump(samples_dir, current, pending_marker, bytes(pending_data))
        pending_marker = None
        pending_data = bytearray()

    def close_current():
        nonlocal current
        flush_pending()
        if current is not None:
            events.append(current)
            current = None

    with log_path.open("r", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            stripped = line.strip()
            mm = MARKER_RE.match(stripped)

            if mm:
                marker = mm.group(1)
                marker_counts[marker] += 1

                flush_pending()

                if marker in EVENT_MARKERS:
                    close_current()
                    current = {
                        "event_index": len(events) + 1,
                        "line": line_no,
                        "marker": marker,
                        "kv": {},
                        "dumps": {},
                    }
                else:
                    pending_marker = marker
                    pending_data = bytearray()

                continue

            if current is None:
                continue

            # Registers / arguments / pseudo-registers
            assigns = parse_assignments(line)
            if assigns:
                current["kv"].update(assigns)

            # Values printed by "? expr"
            val = parse_eval(line)
            if val is not None and pending_marker:
                current["kv"][safe_name(pending_marker)] = val

            # Useful symbol hint for RC4 write / return points
            if "KSecDD!" in line:
                if "symbol_hint" not in current["kv"]:
                    current["kv"]["symbol_hint"] = stripped

            # Dump bytes attached to the latest non-event marker
            if pending_marker:
                b = parse_dump_bytes(line)
                if b:
                    pending_data.extend(b)

    close_current()

    with open(args.jsonl, "w", encoding="utf-8") as out:
        for ev in events:
            out.write(json.dumps(ev, sort_keys=True) + "\n")

    print("[SEED2STATE V23 RC4 REPLAY PARSE REPORT]")
    print(f"file={log_path}")
    print()
    print("[MARKER COUNTS]")
    for k, v in marker_counts.most_common():
        print(f"{k:55s} {v}")

    print()
    print("[EVENT COUNTS]")
    c = Counter(ev["marker"] for ev in events)
    for k, v in sorted(c.items()):
        print(f"{k:55s} {v}")

    print()
    print(f"[EVENTS] {len(events)}")
    if args.pretty:
        for ev in events:
            print(f"#{ev['event_index']} {ev['marker']} line={ev['line']}")
            for k in sorted(ev["kv"]):
                if k in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip", "symbol_hint"):
                    print(f"  {k}={ev['kv'][k]}")
            for name, d in sorted(ev["dumps"].items()):
                print(f"  dump {name}: len={d['len']} head16={d['head16']} sha256={d['sha256']}")

    print()
    print(f"[SAMPLES] wrote={samples_dir}")
    print(f"[JSONL] wrote={args.jsonl}")

if __name__ == "__main__":
    main()
