#!/usr/bin/env python3
import argparse
import re
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


EXPECTED_LEN = 20


def filetime_to_datetime(filetime: int) -> datetime:
    base = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return base + timedelta(microseconds=filetime // 10)


def read_hex_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return "".join(re.findall(r"[0-9A-Fa-f]{2}", text))


def decode_stat_buffer(hexstr: str) -> dict:
    raw = bytes.fromhex(hexstr)

    if len(raw) != EXPECTED_LEN:
        raise ValueError(
            f"invalid buffer length: expected {EXPECTED_LEN} bytes, got {len(raw)}"
        )

    filetime, bytes_recv, smbs_recv, paging = struct.unpack("<QIII", raw)

    try:
        dt = filetime_to_datetime(filetime)
        dt_text = dt.strftime("%Y-%m-%d %H:%M:%S.%f").rstrip("0").rstrip(".")
    except Exception:
        dt_text = f"invalid FILETIME: 0x{filetime:016X}"

    return {
        "StatisticsStartTime": f"0x{filetime:016X}",
        "StatisticsStartTime (UTC)": dt_text,
        "BytesReceived": bytes_recv,
        "SmbsReceived": smbs_recv,
        "PagingReadBytesRequested": paging,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode 20-byte STAT_WORKSTATION_0-like buffers from .hex files."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Input .hex files, for example: sample01_workstation/*.hex",
    )
    args = parser.parse_args()

    exit_code = 0

    for index, filename in enumerate(args.files, 1):
        path = Path(filename)

        print(f"\n--- Buffer {index}: {path} ---")

        try:
            hexstr = read_hex_file(path)
            decoded = decode_stat_buffer(hexstr)

            for key, value in decoded.items():
                print(f"{key:30}: {value}")

        except Exception as exc:
            exit_code = 1
            print(f"Error decoding {path}: {exc}", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
