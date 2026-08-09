#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from xp_sha1 import SHA1_IV, transform_std, transform_ns, words_to_bytes_be


def read_exact(path: Path, size: int) -> bytes:
    data = path.read_bytes()
    if len(data) < size:
        raise SystemExit(f"{path} too short: got 0x{len(data):x}, need 0x{size:x}")
    return data[:size]


def hx(buf: bytes) -> str:
    return " ".join(f"{b:02x}" for b in buf)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Replay the XP FIPS186-style block using two captured SHA-1 compression blocks."
    )
    ap.add_argument("p1_block64", type=Path)
    ap.add_argument("p2_block64", type=Path)
    ap.add_argument("--out40-after", type=Path, default=None)
    args = ap.parse_args()

    p1 = read_exact(args.p1_block64, 0x40)
    p2 = read_exact(args.p2_block64, 0x40)

    out1_std = words_to_bytes_be(transform_std(SHA1_IV, p1))
    out2_std = words_to_bytes_be(transform_std(SHA1_IV, p2))
    replay_std = out1_std + out2_std

    out1_ns = words_to_bytes_be(transform_ns(SHA1_IV, p1))
    out2_ns = words_to_bytes_be(transform_ns(SHA1_IV, p2))
    replay_ns = out1_ns + out2_ns

    print("[FIPS186_XP_SHA1_BLOCK_REPLAY]")
    print(f"out1_std   : {hx(out1_std)}")
    print(f"out2_std   : {hx(out2_std)}")
    print(f"replay_std : {hx(replay_std)}")
    print(f"out1_ns    : {hx(out1_ns)}")
    print(f"out2_ns    : {hx(out2_ns)}")
    print(f"replay_ns  : {hx(replay_ns)}")

    if args.out40_after is not None:
        observed = read_exact(args.out40_after, 0x28)
        print("")
        print("[COMPARE]")
        print(f"observed   : {hx(observed)}")
        print(f"std_match  : {observed == replay_std}")
        print(f"ns_match   : {observed == replay_ns}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
