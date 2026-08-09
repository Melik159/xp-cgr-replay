#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


MARK_RE = re.compile(r"^\[([A-Z0-9_]+)\]\s*$")
DB_RE = re.compile(r"^\s*([0-9a-fA-F]{8})\s+(.+)$")
REG_RE = re.compile(r"\b([a-z]{2,3})=([0-9a-fA-F]{8})")


KEEP_DB_MARKERS = {
    # self-test vectors
    "V26_SELFTEST_STATIC_SEED_6802F8B8",
    "V26_SELFTEST_EXPECTED_AFTER_6802F8CC",
    "V26_SELFTEST_STACK_SOURCE_EBP_M28_AFTER",

    # FIPS local material
    "V26_STATE20_AFTER_FIPS_SLOT",
    "V26_OUT40_LOCAL_AFTER_FIPS_EBP_M40",
    "V26_AUX20_LOCAL_AFTER_FIPS_EBP_M18",

    # output-copy validation
    "V26_OUT40_LOCAL_AFTER_COPY_EBP_M40",
    "V26_OUT_DEST_AFTER_COPY",
}


@dataclass
class Event:
    marker: str
    line: int
    regs: Dict[str, int] = field(default_factory=dict)
    db_lines: List[tuple[int, int, bytes]] = field(default_factory=list)
    copy_index: Optional[int] = None
    copy_len: Optional[int] = None


def parse_db_line(line: str) -> Optional[tuple[int, bytes]]:
    m = DB_RE.match(line)
    if not m:
        return None

    addr = int(m.group(1), 16)
    rest = m.group(2).split("  ")[0].replace("-", " ")

    data: List[int] = []
    for tok in rest.split():
        if re.fullmatch(r"[0-9a-fA-F]{2}", tok):
            data.append(int(tok, 16))

    if not data:
        return None

    return addr, bytes(data)


def collect_events(log_path: pathlib.Path) -> List[Event]:
    events: List[Event] = []
    cur: Optional[Event] = None

    copy_index = 0
    active_copy_index: Optional[int] = None
    active_copy_len: Optional[int] = None

    for no, raw in enumerate(log_path.read_text(errors="replace").splitlines(), 1):
        line = raw.rstrip("\n")

        mm = MARK_RE.match(line.strip())
        if mm:
            marker = mm.group(1)

            if marker == "V26_AFTER_OUT_COPY_6800D713":
                copy_index += 1
                active_copy_index = copy_index
                active_copy_len = None

            cur = Event(
                marker=marker,
                line=no,
                copy_index=active_copy_index,
                copy_len=active_copy_len,
            )
            events.append(cur)
            continue

        if cur is None:
            continue

        for reg, value in REG_RE.findall(line):
            cur.regs[reg] = int(value, 16)

        # At V26_AFTER_OUT_COPY_6800D713, ESI contains the effective copy length.
        if cur.marker == "V26_AFTER_OUT_COPY_6800D713" and "esi" in cur.regs:
            active_copy_len = cur.regs["esi"]
            cur.copy_len = active_copy_len

        # Propagate copy context to following submarkers.
        if cur.marker in {
            "V26_OUT_DEST_AFTER_COPY",
            "V26_OUT40_LOCAL_AFTER_COPY_EBP_M40",
        }:
            cur.copy_index = active_copy_index
            cur.copy_len = active_copy_len

        parsed = parse_db_line(line)
        if parsed:
            addr, data = parsed
            cur.db_lines.append((no, addr, data))

    return events


def event_blob(event: Event) -> tuple[Optional[int], bytes, Optional[int], Optional[int]]:
    if not event.db_lines:
        return None, b"", None, None

    first_line = event.db_lines[0][0]
    last_line = event.db_lines[-1][0]
    first_addr = event.db_lines[0][1]

    out = bytearray()
    for _, _, data in event.db_lines:
        out.extend(data)

    return first_addr, bytes(out), first_line, last_line


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def classify(marker: str) -> str:
    if "SELFTEST" in marker:
        return "selftest"
    if "STATE20" in marker:
        return "state20"
    if "AUX20" in marker:
        return "aux20"
    if "OUT40" in marker:
        return "out40"
    if "OUT_DEST" in marker:
        return "out_dest"
    return "other"


def sample_size(event: Event, blob: bytes) -> int:
    marker = event.marker

    if marker == "V26_OUT_DEST_AFTER_COPY":
        # Critical point:
        # destination is only valid for the copied prefix.
        # Example: len=0x20 or len=0x0a, not always 0x28.
        if event.copy_len and 0 < event.copy_len <= 40:
            return min(len(blob), event.copy_len)
        return min(len(blob), 40)

    if marker == "V26_AUX20_LOCAL_AFTER_FIPS_EBP_M18":
        return min(len(blob), 20)

    if marker.startswith("V26_SELFTEST_"):
        return min(len(blob), 20)

    # Keep full public useful width for state20/out40 samples.
    if "STATE20" in marker or "OUT40" in marker:
        return min(len(blob), 40)

    return len(blob)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="full KD log or redacted KD log")
    ap.add_argument("--outdir", required=True, help="sample output directory, e.g. samples/sample01")
    args = ap.parse_args()

    log_path = pathlib.Path(args.log)
    outdir = pathlib.Path(args.outdir)
    blobs_dir = outdir / "blobs"

    if not log_path.exists():
        raise SystemExit(f"missing log: {log_path}")

    blobs_dir.mkdir(parents=True, exist_ok=True)

    events = collect_events(log_path)

    manifest = []
    counters: Dict[str, int] = {}

    for event in events:
        if event.marker not in KEEP_DB_MARKERS:
            continue

        addr, blob, first_line, last_line = event_blob(event)
        if not blob or addr is None:
            continue

        n = counters.get(event.marker, 0) + 1
        counters[event.marker] = n

        size = sample_size(event, blob)
        sample = blob[:size]

        copy_part = ""
        if event.copy_index is not None and event.marker in {
            "V26_OUT_DEST_AFTER_COPY",
            "V26_OUT40_LOCAL_AFTER_COPY_EBP_M40",
        }:
            copy_part = f"_copy{event.copy_index:02d}_len{event.copy_len or 0:02x}"

        fname = f"{n:04d}_{safe_name(event.marker)}{copy_part}_{addr:08x}_{size:02x}.bin"
        fpath = blobs_dir / fname
        fpath.write_bytes(sample)

        manifest.append({
            "index": n,
            "marker": event.marker,
            "class": classify(event.marker),
            "line_first": first_line,
            "line_last": last_line,
            "address": f"0x{addr:08x}",
            "size": size,
            "file": f"blobs/{fname}",
            "hex": sample.hex(),
            "copy_index": event.copy_index,
            "copy_len": event.copy_len,
            "regs": {k: f"0x{v:08x}" for k, v in sorted(event.regs.items())},
        })

    manifest_json = outdir / "manifest.json"
    manifest_tsv = outdir / "manifest.tsv"

    manifest_json.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with manifest_tsv.open("w", encoding="utf-8") as f:
        f.write("marker\tclass\tcopy_index\tcopy_len\taddress\tsize\tfile\tline_first\tline_last\thex\n")
        for m in manifest:
            f.write(
                f"{m['marker']}\t{m['class']}\t{m['copy_index']}\t{m['copy_len']}\t"
                f"{m['address']}\t{m['size']}\t{m['file']}\t"
                f"{m['line_first']}\t{m['line_last']}\t{m['hex']}\n"
            )

    print(f"events_total={len(events)}")
    print(f"samples_written={len(manifest)}")
    print(f"outdir={outdir}")
    print(f"manifest={manifest_json}")
    print(f"manifest_tsv={manifest_tsv}")

    by_class: Dict[str, int] = {}
    for m in manifest:
        by_class[m["class"]] = by_class.get(m["class"], 0) + 1

    for k in sorted(by_class):
        print(f"class.{k}={by_class[k]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
