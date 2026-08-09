#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


MARKER_RE = re.compile(r"^\[([A-Z0-9_]+)\]")
DB_LINE_RE = re.compile(r"^([0-9a-fA-F]{8})\s+")

KNOWN_RET_TO_LABEL = {
    0x68011CAA: "selftest",
    0x680120D4: "init",
    0x6800D766: "bridge00",
    0x6800D7DA: "runtime",
}


@dataclass
class Block:
    marker: str
    lines: list[str] = field(default_factory=list)
    mem: dict[int, int] = field(default_factory=dict)
    regs: dict[str, int] = field(default_factory=dict)
    meta: dict[str, int] = field(default_factory=dict)


def parse_hex_int(s: str) -> int:
    return int(s, 16)


def parse_db_line(line: str) -> tuple[int, bytes] | None:
    m = DB_LINE_RE.match(line)
    if not m:
        return None

    addr = int(m.group(1), 16)

    # WinDbg db format:
    # 0013fdb0  5a 9d 13 e5 ee a7 f9 59-0d 0d 86 ab c8 ac a7 e8  Z...
    # dd lines start with 8-hex tokens, so reject those.
    byte_columns = line[10:60].replace("-", " ")
    toks = byte_columns.split()
    if not toks:
        return None
    if len(toks[0]) != 2:
        return None

    bs: list[int] = []
    for t in toks:
        if re.fullmatch(r"[0-9a-fA-F]{2}", t):
            bs.append(int(t, 16))

    if not bs:
        return None
    return addr, bytes(bs)


def parse_block_metadata(block: Block) -> None:
    for line in block.lines:
        # Register line
        if line.startswith("eax="):
            for k, v in re.findall(r"\b(eax|ebx|ecx|edx|esi|edi)=([0-9a-fA-F]{8})", line):
                block.regs[k] = parse_hex_int(v)

        if line.startswith("eip="):
            for k, v in re.findall(r"\b(eip|esp|ebp)=([0-9a-fA-F]{8})", line):
                block.regs[k] = parse_hex_int(v)

        # FIPS entry line:
        # state=68031958 aux=0013f6f4 out=0013f6cc len_or_flags=00000014 ret=6800d6fb
        m = re.search(
            r"state=([0-9a-fA-F]{8})\s+aux=([0-9a-fA-F]{8})\s+out=([0-9a-fA-F]{8})"
            r"\s+len_or_flags=([0-9a-fA-F]{8})\s+ret=([0-9a-fA-F]{8})",
            line,
        )
        if m:
            block.meta["state"] = parse_hex_int(m.group(1))
            block.meta["aux"] = parse_hex_int(m.group(2))
            block.meta["out"] = parse_hex_int(m.group(3))
            block.meta["len_or_flags"] = parse_hex_int(m.group(4))
            block.meta["entry_ret"] = parse_hex_int(m.group(5))

        # FIPS return line:
        # out=0013fdb0 state=68031958 ret=6800d766
        m = re.search(
            r"out=([0-9a-fA-F]{8})\s+state=([0-9a-fA-F]{8})\s+ret=([0-9a-fA-F]{8})",
            line,
        )
        if m:
            block.meta["out"] = parse_hex_int(m.group(1))
            block.meta["state"] = parse_hex_int(m.group(2))
            block.meta["caller_ret"] = parse_hex_int(m.group(3))

        # Aux destination line:
        # aux_dst=0013f6f4
        m = re.search(r"aux_dst=([0-9a-fA-F]{8})", line)
        if m:
            block.meta["aux_dst"] = parse_hex_int(m.group(1))

        parsed = parse_db_line(line)
        if parsed:
            addr, bs = parsed
            for i, b in enumerate(bs):
                block.mem[addr + i] = b


def split_blocks(text: str) -> list[Block]:
    blocks: list[Block] = []
    cur: Block | None = None

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        m = MARKER_RE.match(line)
        if m:
            if cur is not None:
                parse_block_metadata(cur)
                blocks.append(cur)
            cur = Block(marker=m.group(1), lines=[line])
        elif cur is not None:
            cur.lines.append(line)

    if cur is not None:
        parse_block_metadata(cur)
        blocks.append(cur)

    return blocks


def read_mem(block: Block, addr: int, n: int, ctx: str) -> bytes:
    missing = [addr + i for i in range(n) if addr + i not in block.mem]
    if missing:
        raise RuntimeError(f"missing memory for {ctx}: addr=0x{addr:08x} len={n}, first_missing=0x{missing[0]:08x}")
    return bytes(block.mem[addr + i] for i in range(n))


def first_db_bytes(block: Block, n: int, ctx: str) -> bytes:
    if not block.mem:
        raise RuntimeError(f"no db bytes found for {ctx}")
    addrs = sorted(block.mem)
    start = addrs[0]
    return read_mem(block, start, n, ctx)


@dataclass
class Transition:
    label: str
    caller_ret: int
    aux_after: Block | None
    fips_entry: Block
    fips_return: Block


def build_transitions(blocks: list[Block]) -> tuple[dict[str, Transition], bytes]:
    transitions: dict[str, Transition] = {}

    pending_aux_after: Block | None = None
    pending_fips_entry: Block | None = None
    bridge_count = 0
    cgr_output32: bytes | None = None

    for block in blocks:
        marker = block.marker

        if marker == "V29_PROVIDER_AUX_AFTER_SYSTEMFUNCTION036_6800D69E":
            pending_aux_after = block
            continue

        if marker == "V29_PROVIDER_FIPS_ENTRY_68027101":
            pending_fips_entry = block
            continue

        if marker == "V29_PROVIDER_FIPS_RETURN_6800D6FB":
            if pending_fips_entry is None:
                raise RuntimeError("FIPS return without pending FIPS entry")

            caller_ret = block.meta.get("caller_ret")
            if caller_ret is None:
                raise RuntimeError("FIPS return block has no caller_ret")

            label = KNOWN_RET_TO_LABEL.get(caller_ret)
            if label is None:
                label = f"bridge{bridge_count:02d}"
                bridge_count += 1

            tr = Transition(
                label=label,
                caller_ret=caller_ret,
                aux_after=pending_aux_after,
                fips_entry=pending_fips_entry,
                fips_return=block,
            )

            # selftest is kept out of the composed G sample.
            if label != "selftest":
                transitions[label] = tr

            pending_fips_entry = None
            pending_aux_after = None
            continue

        if marker == "V29_CGR_OUTPUT32":
            cgr_output32 = first_db_bytes(block, 32, "cgr_output32")
            continue

    for required in ["init", "bridge00", "runtime"]:
        if required not in transitions:
            raise RuntimeError(f"missing required transition: {required}")

    if cgr_output32 is None:
        raise RuntimeError("missing V29_CGR_OUTPUT32 block")

    return transitions, cgr_output32


def transition_blobs(tr: Transition) -> dict[str, bytes]:
    entry = tr.fips_entry
    ret = tr.fips_return

    state_addr = entry.meta.get("state")
    aux_addr = entry.meta.get("aux")
    out_addr_ret = ret.meta.get("out")
    state_addr_ret = ret.meta.get("state")

    if state_addr is None or aux_addr is None:
        raise RuntimeError(f"{tr.label}: incomplete FIPS entry metadata")
    if out_addr_ret is None or state_addr_ret is None:
        raise RuntimeError(f"{tr.label}: incomplete FIPS return metadata")

    if tr.aux_after is None:
        raise RuntimeError(f"{tr.label}: missing SystemFunction036 after block")

    aux_dst = tr.aux_after.meta.get("aux_dst")
    if aux_dst is None:
        raise RuntimeError(f"{tr.label}: aux_after block has no aux_dst")

    state20_before = read_mem(entry, state_addr, 20, f"{tr.label}.state20_before")
    sysfunc036_raw20 = read_mem(tr.aux_after, aux_dst, 20, f"{tr.label}.sysfunc036_raw20")
    aux20_final = read_mem(entry, aux_addr, 20, f"{tr.label}.aux20_final")

    # Important:
    # The FIPS-entry `out=` pointer is the local out40 destination for rsaenh+0x27101.
    # It is not the provider output buffer used earlier by the local XOR step.
    #
    # The actual XOR delta is observed by comparing the local aux buffer immediately
    # after SystemFunction036 with the aux buffer as passed into the FIPS block.
    outbuf_prefix20 = bytes(a ^ b for a, b in zip(sysfunc036_raw20, aux20_final))

    return {
        "state20_before": state20_before,
        "sysfunc036_raw20": sysfunc036_raw20,
        "outbuf_prefix20": outbuf_prefix20,
        "aux20_final": aux20_final,
        "out40": read_mem(ret, out_addr_ret, 40, f"{tr.label}.out40"),
        "state20_after": read_mem(ret, state_addr_ret, 20, f"{tr.label}.state20_after"),
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_sample(sample_dir: Path, transitions: dict[str, Transition], cgr_output32: bytes) -> dict:
    blobs_dir = sample_dir / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries: list[dict] = []

    def put(name: str, data: bytes) -> None:
        path = blobs_dir / name
        path.write_bytes(data)
        manifest_entries.append({
            "path": str(path.relative_to(sample_dir)),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    for label in ["init", "bridge00", "runtime"]:
        blobs = transition_blobs(transitions[label])
        put(f"{label}_state20_before.bin", blobs["state20_before"])
        put(f"{label}_sysfunc036_raw20.bin", blobs["sysfunc036_raw20"])
        put(f"{label}_outbuf_prefix20.bin", blobs["outbuf_prefix20"])
        put(f"{label}_aux20_final.bin", blobs["aux20_final"])
        put(f"{label}_out40.bin", blobs["out40"])
        put(f"{label}_state20_after.bin", blobs["state20_after"])

    put("cgr_output32.bin", cgr_output32)

    manifest = {
        "campaign": "seed2state_v29_g_composed_provider_bridge",
        "sample": "sample01",
        "model": "G_provider = G_init + G_acquire_bridge_00 + G_runtime_measured",
        "files": manifest_entries,
    }

    (sample_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    with (sample_dir / "manifest.tsv").open("w") as f:
        f.write("path\tsize\tsha256\n")
        for e in manifest_entries:
            f.write(f"{e['path']}\t{e['size']}\t{e['sha256']}\n")

    (sample_dir / "README.md").write_text(
        "# sample01\n\n"
        "Extracted sample for V29 composed provider-side G validation.\n\n"
        "This sample contains three sequential provider transitions:\n\n"
        "```text\n"
        "init\n"
        "→ bridge00\n"
        "→ runtime measured\n"
        "```\n\n"
        "The measured CGR output is stored in `blobs/cgr_output32.bin`.\n"
    )

    return manifest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", type=Path)
    ap.add_argument("--write-sample", type=Path, required=True)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    text = args.log.read_text(errors="replace")
    blocks = split_blocks(text)
    transitions, cgr_output32 = build_transitions(blocks)
    manifest = write_sample(args.write_sample, transitions, cgr_output32)

    summary = {
        "blocks": len(blocks),
        "transitions": {k: f"0x{v.caller_ret:08x}" for k, v in transitions.items()},
        "cgr_output32_len": len(cgr_output32),
        "sample_dir": str(args.write_sample),
        "manifest": manifest,
    }

    if args.json:
        args.json.write_text(json.dumps(summary, indent=2) + "\n")

    print("[V29_PARSE_OK]")
    print(f"blocks={len(blocks)}")
    for k in ["init", "bridge00", "runtime"]:
        print(f"{k}_ret=0x{transitions[k].caller_ret:08x}")
    print(f"sample_dir={args.write_sample}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
