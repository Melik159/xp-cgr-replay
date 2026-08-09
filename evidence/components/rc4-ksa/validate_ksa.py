#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


def sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def read_exact(path: Path, size: int) -> bytes:
    data = path.read_bytes()
    if len(data) < size:
        raise ValueError(f"{path} too short: got 0x{len(data):x}, need 0x{size:x}")
    return data[:size]


def validate_ksa(sample_dir: Path, out_dir: Path) -> bool:
    k = read_exact(sample_dir / "K_before.bin", 256)
    s0 = read_exact(sample_dir / "S_before.bin", 256)
    s_obs = read_exact(sample_dir / "S_after.bin", 256)

    out_dir.mkdir(parents=True, exist_ok=True)

    log_path = out_dir / "result.log"
    trace_path = out_dir / "trace.csv"
    summary_path = out_dir / "summary.txt"

    with log_path.open("w", encoding="utf-8") as log, trace_path.open(
        "w", newline="", encoding="utf-8"
    ) as csvf:
        writer = csv.writer(csvf)
        writer.writerow([
            "i",
            "K[i]",
            "S_i_before",
            "j_before",
            "j_after",
            "S_j_before",
            "S_i_after",
            "S_j_after",
        ])

        def logp(line: str = "") -> None:
            print(line)
            log.write(line + "\n")

        logp("[RC4_KSA_REPLAY]")
        logp(f"K_sha1      : {sha1_hex(k)}")
        logp(f"S_before_sha1: {sha1_hex(s0)}")
        logp(f"S_after_sha1 : {sha1_hex(s_obs)}")
        logp()

        s = list(s0)
        j = 0

        for i in range(256):
            key_byte = k[i]
            s_i_before = s[i]
            j_before = j

            j = (j + s_i_before + key_byte) & 0xFF
            s_j_before = s[j]

            s[i], s[j] = s[j], s[i]

            writer.writerow([
                f"{i:02x}",
                f"{key_byte:02x}",
                f"{s_i_before:02x}",
                f"{j_before:02x}",
                f"{j:02x}",
                f"{s_j_before:02x}",
                f"{s[i]:02x}",
                f"{s[j]:02x}",
            ])

        s_calc = bytes(s)
        match = s_calc == s_obs

        logp("[FINAL]")
        logp(f"match       : {'OK' if match else 'MISMATCH'}")
        logp(f"j_final     : {j:02x}")
        logp(f"S_calc_sha1 : {sha1_hex(s_calc)}")
        logp(f"S_obs_sha1  : {sha1_hex(s_obs)}")

        diffs = []
        for off, (a, b) in enumerate(zip(s_calc, s_obs)):
            if a != b:
                for bit in range(8):
                    if ((a >> bit) & 1) != ((b >> bit) & 1):
                        diffs.append((off, bit, a, b))

        logp()
        logp("[BIT_CHECK]")
        if not diffs:
            logp("BIT_EXACT_MATCH: 2048 bits")
        else:
            logp(f"DIFFS: {len(diffs)}")
            for off, bit, a, b in diffs[:50]:
                logp(f"byte={off:02x} bit={bit} calc={a:02x} obs={b:02x}")

    summary_path.write_text(
        "\n".join([
            "RC4 KSA VALIDATION",
            f"match={'OK' if match else 'MISMATCH'}",
            f"j_final={j:02x}",
            f"K_sha1={sha1_hex(k)}",
            f"S_before_sha1={sha1_hex(s0)}",
            f"S_after_sha1={sha1_hex(s_obs)}",
            f"S_calc_sha1={sha1_hex(s_calc)}",
            "",
        ]),
        encoding="utf-8",
    )

    return match


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay RC4 KSA from a captured 256-byte key and compare the resulting S-box."
    )
    parser.add_argument(
        "--sample-dir",
        type=Path,
        default=Path("sample01"),
        help="Directory containing K_before.bin, S_before.bin, and S_after.bin",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Directory where result.log, trace.csv, and summary.txt are written",
    )

    args = parser.parse_args()

    ok = validate_ksa(args.sample_dir, args.out_dir)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
