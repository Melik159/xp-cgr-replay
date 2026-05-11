#!/usr/bin/env python3
"""
Parse a WinDbg/KD trace for the rsaenh provider-initialization aux-mix path.

Campaign target:
    sub_68012051+0x7e / 680120CF
      -> sub_6800D640
      -> SystemFunction036([ebp-18], 0x14)
      -> aux20_final = SystemFunction036_raw20 XOR output-buffer-prefix20
      -> fips block @ 68027101
      -> state20_after at 68031958

The parser is intentionally narrow: it expects the markers emitted by the
manual V28-style run and extracts a single sample.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

MARKER_RE = re.compile(r"^\[(GSTATE_[A-Z0-9_]+)\]")
REG_RE = re.compile(r"\b(eax|ebx|ecx|edx|esi|edi|eip|esp|ebp)=([0-9a-fA-F]{8})\b")
FIPS_PTR_RE = re.compile(
    r"state=([0-9a-fA-F]{8})\s+aux=([0-9a-fA-F]{8})\s+out=([0-9a-fA-F]{8})\s+len_or_flags=([0-9a-fA-F]{8})"
)
AUX_DST_RE = re.compile(r"aux_dst=([0-9a-fA-F]{8})")
ADDR_RE = re.compile(r"^([0-9a-fA-F]{8})\s+(.*)$")
DWORD_RE = re.compile(r"^[0-9a-fA-F]{8}$")
BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")

REQUIRED_MARKERS = [
    "GSTATE_INIT_CALL_680120CF_BEFORE_SUB_6800D640",
    "GSTATE_INIT_AUX_BEFORE_SYSTEMFUNCTION036_6800D693",
    "GSTATE_INIT_AUX_AFTER_SYSTEMFUNCTION036_6800D69E",
    "GSTATE_INIT_FIPS_ENTRY_68027101",
    "GSTATE_INIT_RETURN_680120D4_AFTER_SUB_6800D640",
]


def bhex(b: bytes) -> str:
    return b.hex()


def grouped_hex(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class SparseMemory:
    """Sparse byte-addressable memory reconstructed from dd/db log lines."""

    def __init__(self) -> None:
        self._m: Dict[int, int] = {}

    def put(self, addr: int, data: bytes) -> None:
        for i, x in enumerate(data):
            self._m[addr + i] = x

    def get(self, addr: int, length: int) -> Optional[bytes]:
        out = []
        for i in range(length):
            v = self._m.get(addr + i)
            if v is None:
                return None
            out.append(v)
        return bytes(out)

    def get_dword_le(self, addr: int) -> Optional[int]:
        b = self.get(addr, 4)
        if b is None:
            return None
        return int.from_bytes(b, "little")

    def merge(self, other: "SparseMemory") -> None:
        self._m.update(other._m)


@dataclass
class Block:
    marker: str
    lines: List[str]
    regs: Dict[str, int]
    mem: SparseMemory
    aux_dst: Optional[int] = None
    fips_state: Optional[int] = None
    fips_aux: Optional[int] = None
    fips_out: Optional[int] = None
    fips_len_or_flags: Optional[int] = None


def parse_db_or_dd_line(line: str) -> Optional[Tuple[int, bytes]]:
    """Parse WinDbg db/dd dump lines into bytes.

    dd example:
        0013f700  00000000 00000000 0013f724 00000028
    db example:
        68031958  24 c5 06 c0 44 5b 81 78-6d c9 ...  $...D[.x
    """
    m = ADDR_RE.match(line.rstrip())
    if not m:
        return None
    addr = int(m.group(1), 16)
    rest = m.group(2).replace("-", " ")
    toks = rest.split()
    if not toks:
        return None

    # dd line: a run of 8-hex-digit dwords. Convert little-endian.
    if len(toks) >= 2 and all(DWORD_RE.match(t) for t in toks[: min(len(toks), 8)]):
        dwords: List[int] = []
        for t in toks:
            if not DWORD_RE.match(t):
                break
            dwords.append(int(t, 16))
        if dwords:
            return addr, b"".join(x.to_bytes(4, "little") for x in dwords)

    # db line: a run of 2-hex-digit bytes, followed by ASCII columns.
    bytes_out: List[int] = []
    for t in toks:
        if not BYTE_RE.match(t):
            break
        bytes_out.append(int(t, 16))
    if bytes_out:
        return addr, bytes(bytes_out)
    return None


def parse_log(path: Path) -> Dict[str, Block]:
    blocks: Dict[str, Block] = {}
    current: Optional[Block] = None

    for raw in path.read_text(errors="replace").splitlines():
        mm = MARKER_RE.match(raw)
        if mm:
            marker = mm.group(1)
            current = Block(marker=marker, lines=[], regs={}, mem=SparseMemory())
            blocks[marker] = current
            continue
        if current is None:
            continue

        current.lines.append(raw)

        for name, val in REG_RE.findall(raw):
            current.regs[name] = int(val, 16)

        am = AUX_DST_RE.search(raw)
        if am:
            current.aux_dst = int(am.group(1), 16)

        fm = FIPS_PTR_RE.search(raw)
        if fm:
            current.fips_state = int(fm.group(1), 16)
            current.fips_aux = int(fm.group(2), 16)
            current.fips_out = int(fm.group(3), 16)
            current.fips_len_or_flags = int(fm.group(4), 16)

        parsed = parse_db_or_dd_line(raw)
        if parsed:
            addr, data = parsed
            current.mem.put(addr, data)

    return blocks


def bxor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor operands have different lengths")
    return bytes(x ^ y for x, y in zip(a, b))


def extract_sample(blocks: Dict[str, Block]) -> Dict[str, object]:
    missing = [m for m in REQUIRED_MARKERS if m not in blocks]
    if missing:
        raise RuntimeError(f"missing required marker(s): {', '.join(missing)}")

    call = blocks["GSTATE_INIT_CALL_680120CF_BEFORE_SUB_6800D640"]
    aux_before_blk = blocks["GSTATE_INIT_AUX_BEFORE_SYSTEMFUNCTION036_6800D693"]
    aux_after_blk = blocks["GSTATE_INIT_AUX_AFTER_SYSTEMFUNCTION036_6800D69E"]
    fips = blocks["GSTATE_INIT_FIPS_ENTRY_68027101"]
    ret = blocks["GSTATE_INIT_RETURN_680120D4_AFTER_SUB_6800D640"]

    esp = call.regs.get("esp")
    if esp is None:
        raise RuntimeError("could not parse ESP at 680120CF")
    outbuf_ptr = call.mem.get_dword_le(esp + 0x10)
    out_len = call.mem.get_dword_le(esp + 0x14)
    if outbuf_ptr is None or out_len is None:
        raise RuntimeError("could not recover sub_6800D640 out buffer/length from call stack")

    state_ptr = fips.fips_state
    aux_ptr = fips.fips_aux
    fips_out_ptr = fips.fips_out
    if state_ptr is None or aux_ptr is None or fips_out_ptr is None:
        raise RuntimeError("could not recover FIPS state/aux/out pointers")

    aux_dst = aux_after_blk.aux_dst or aux_before_blk.aux_dst or aux_ptr

    state20_before = fips.mem.get(state_ptr, 20)
    if state20_before is None:
        state20_before = call.mem.get(0x68031958, 20)
    if state20_before is None:
        raise RuntimeError("missing state20_before bytes")

    sysfunc036_raw20 = aux_after_blk.mem.get(aux_dst, 20)
    if sysfunc036_raw20 is None:
        raise RuntimeError("missing SystemFunction036 raw aux20 bytes")

    aux20_final = fips.mem.get(aux_ptr, 20)
    if aux20_final is None:
        raise RuntimeError("missing final aux20 bytes at FIPS entry")

    outbuf_prefix20 = bxor(sysfunc036_raw20, aux20_final)

    state20_after = ret.mem.get(0x68031958, 20)
    if state20_after is None:
        raise RuntimeError("missing state20_after bytes")

    out40_init = ret.mem.get(outbuf_ptr, 40)
    if out40_init is None:
        # In some logs the caller out buffer is absent at return; try local FIPS out.
        out40_init = ret.mem.get(fips_out_ptr, 40)
    if out40_init is None:
        raise RuntimeError(
            f"missing out40 bytes; expected caller out buffer {outbuf_ptr:08x} or local FIPS out {fips_out_ptr:08x}"
        )

    sample = {
        "campaign": "seed2state_v28_provider_init_auxmix",
        "sample_id": "sample01",
        "markers_seen": sorted(blocks.keys()),
        "addresses": {
            "g_state20_slot": "68031958",
            "init_call": "680120cf",
            "provider_rng_wrapper": "6800d640",
            "systemfunction036_thunk": "6801504c",
            "systemfunction036_callsite_before": "6800d693",
            "systemfunction036_callsite_after": "6800d69e",
            "fips_entry": "68027101",
            "init_return": "680120d4",
            "aux_dst": f"{aux_dst:08x}",
            "caller_outbuf": f"{outbuf_ptr:08x}",
            "fips_local_out": f"{fips_out_ptr:08x}",
        },
        "lengths": {
            "aux_len": 20,
            "out_len_arg": out_len,
            "fips_len_or_flags": fips.fips_len_or_flags,
        },
        "blobs_hex": {
            "state20_before": bhex(state20_before),
            "sysfunc036_raw20": bhex(sysfunc036_raw20),
            "outbuf_prefix20": bhex(outbuf_prefix20),
            "aux20_final": bhex(aux20_final),
            "out40_init": bhex(out40_init),
            "state20_after": bhex(state20_after),
        },
    }
    return sample


def write_sample(sample: Dict[str, object], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    blobs_dir = outdir / "blobs"
    blobs_dir.mkdir(exist_ok=True)
    blobs_hex = sample["blobs_hex"]  # type: ignore[index]
    assert isinstance(blobs_hex, dict)

    blob_files = {}
    for name, hx in blobs_hex.items():
        p = blobs_dir / f"{name}.bin"
        p.write_bytes(bytes.fromhex(str(hx)))
        blob_files[name] = {
            "path": str(p.relative_to(outdir)),
            "len": p.stat().st_size,
            "sha256": sha256_hex(p),
            "hex": str(hx),
        }

    manifest = dict(sample)
    manifest["blob_files"] = blob_files
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    with (outdir / "manifest.tsv").open("w") as f:
        f.write("name\tlen\tsha256\thex\tpath\n")
        for name, meta in blob_files.items():
            f.write(f"{name}\t{meta['len']}\t{meta['sha256']}\t{meta['hex']}\t{meta['path']}\n")

    (outdir / "README.md").write_text(
        "# sample01\n\n"
        "Extracted from the provider-initialization aux-mix WinDbg/KD trace.\n\n"
        "Core relation:\n\n"
        "```text\n"
        "aux20_final = SystemFunction036_raw20 XOR outbuf_prefix20\n"
        "FIPS186_block(state20_before, aux20_final) -> out40_init, state20_after\n"
        "```\n"
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", type=Path, help="WinDbg log to parse")
    ap.add_argument("--json", type=Path, help="write result JSON")
    ap.add_argument("--write-sample", type=Path, help="write extracted sample directory")
    args = ap.parse_args(argv)

    blocks = parse_log(args.log)
    sample = extract_sample(blocks)

    text = json.dumps(sample, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text)
    else:
        print(text, end="")

    if args.write_sample:
        write_sample(sample, args.write_sample)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
