#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Optional


def read_exact(path: Path, expected_size: int) -> bytes:
    data = path.read_bytes()
    if len(data) != expected_size:
        raise ValueError(
            f"{path} has size 0x{len(data):x}, expected 0x{expected_size:x}"
        )
    return data


def parse_hex(value: str, expected_size: int) -> bytes:
    clean = "".join(ch for ch in value if ch in "0123456789abcdefABCDEF")
    if len(clean) % 2 != 0:
        raise ValueError("hex input has an odd number of digits")
    data = bytes.fromhex(clean)
    if len(data) != expected_size:
        raise ValueError(
            f"hex input has size 0x{len(data):x}, expected 0x{expected_size:x}"
        )
    return data


def load_input(name: str, file_arg: Optional[str], hex_arg: Optional[str], size: int) -> bytes:
    if file_arg and hex_arg:
        raise ValueError(f"{name}: provide either a file or a hex value, not both")
    if file_arg:
        return read_exact(Path(file_arg), size)
    if hex_arg:
        return parse_hex(hex_arg, size)
    raise ValueError(f"{name}: missing input")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor inputs must have identical length")
    return bytes(x ^ y for x, y in zip(a, b))


def add_u160_be(a: bytes, b: bytes, carry: int = 0) -> bytes:
    if len(a) != 20 or len(b) != 20:
        raise ValueError("add_u160_be expects two 20-byte inputs")

    x = int.from_bytes(a, "big")
    y = int.from_bytes(b, "big")
    z = (x + y + carry) % (1 << 160)
    return z.to_bytes(20, "big")


def replay_fips186_style_block(state20: bytes, aux20: bytes) -> dict[str, bytes]:
    """
    Replay the high-level XP FIPS186-style arithmetic construction.

    This function models the observed 160-bit additions and SHA-1 digest
    operations used to derive the 40-byte output buffer from the captured
    state20 and aux20 inputs.
    """
    if len(state20) != 20 or len(aux20) != 20:
        raise ValueError("state20 and aux20 must both be 20 bytes")

    tmp0 = add_u160_be(state20, aux20)
    x0 = hashlib.sha1(tmp0).digest()
    part0 = add_u160_be(state20, x0, carry=1)

    tmp1 = add_u160_be(part0, aux20)
    x1 = hashlib.sha1(tmp1).digest()
    part1 = add_u160_be(part0, x1, carry=1)

    out40 = part0 + part1
    cgr_0x20 = out40[:0x20]

    return {
        "tmp0": tmp0,
        "x0": x0,
        "part0": part0,
        "tmp1": tmp1,
        "x1": x1,
        "part1": part1,
        "out40": out40,
        "cgr_0x20": cgr_0x20,
    }


def hx(data: bytes) -> str:
    return data.hex()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Replay the provider local XOR stage and the XP FIPS186-style "
            "output construction from captured inputs."
        )
    )

    parser.add_argument("--state20-file")
    parser.add_argument("--state20-hex")

    parser.add_argument("--local-before-file")
    parser.add_argument("--local-before-hex")

    parser.add_argument("--src20-file")
    parser.add_argument("--src20-hex")

    parser.add_argument("--local-after-file")
    parser.add_argument("--local-after-hex")

    parser.add_argument("--out40-file")
    parser.add_argument("--out40-hex")

    parser.add_argument("--cgr-file")
    parser.add_argument("--cgr-hex")

    parser.add_argument("--quiet", action="store_true")

    args = parser.parse_args()

    try:
        state20 = load_input("state20", args.state20_file, args.state20_hex, 20)
        local_before = load_input(
            "local_before", args.local_before_file, args.local_before_hex, 20
        )
        src20 = load_input("src20", args.src20_file, args.src20_hex, 20)

        local_after = None
        if args.local_after_file or args.local_after_hex:
            local_after = load_input(
                "local_after", args.local_after_file, args.local_after_hex, 20
            )

        out40_expected = None
        if args.out40_file or args.out40_hex:
            out40_expected = load_input("out40", args.out40_file, args.out40_hex, 40)

        cgr_expected = None
        if args.cgr_file or args.cgr_hex:
            cgr_expected = load_input("cgr", args.cgr_file, args.cgr_hex, 32)

    except Exception as exc:
        print(f"[ERROR] input failure: {exc}", file=sys.stderr)
        return 1

    aux20 = xor_bytes(local_before, src20)

    if not args.quiet:
        print("[INPUTS]")
        print(f"{'state20':14}: {hx(state20)}")
        print(f"{'local_before':14}: {hx(local_before)}")
        print(f"{'src20':14}: {hx(src20)}")
        if local_after is not None:
            print(f"{'local_after':14}: {hx(local_after)}")
        if out40_expected is not None:
            print(f"{'out40_expected':14}: {hx(out40_expected)}")
        if cgr_expected is not None:
            print(f"{'cgr_expected':14}: {hx(cgr_expected)}")
        print()

    print("[PROVIDER_LOCAL_XOR_REPLAY]")
    print(f"{'aux20':14}: {hx(aux20)}")

    if local_after is not None:
        xor_ok = aux20 == local_after
        print(f"{'xor_match':14}: {'OK' if xor_ok else 'MISMATCH'}")
        if not xor_ok:
            return 2
    else:
        print(f"{'xor_match':14}: not checked")

    print()

    replay = replay_fips186_style_block(state20, aux20)

    print("[FIPS186_XP_HIGH_LEVEL_REPLAY]")
    for name in ("tmp0", "x0", "part0", "tmp1", "x1", "part1", "out40", "cgr_0x20"):
        print(f"{name:14}: {hx(replay[name])}")

    if out40_expected is not None:
        out40_ok = replay["out40"] == out40_expected
        print(f"{'out40_match':14}: {'OK' if out40_ok else 'MISMATCH'}")
        if not out40_ok:
            return 3

    if cgr_expected is not None:
        cgr_ok = replay["cgr_0x20"] == cgr_expected
        print(f"{'cgr_match':14}: {'OK' if cgr_ok else 'MISMATCH'}")
        if not cgr_ok:
            return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
