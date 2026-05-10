#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
from typing import Iterable, Tuple

MASK160 = (1 << 160) - 1

SHA1_IV = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)


def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1_compress_one_block(block64: bytes, h: Tuple[int, int, int, int, int] = SHA1_IV) -> bytes:
    if len(block64) != 64:
        raise ValueError(f"SHA1 compression requires exactly 64 bytes, got {len(block64)}")

    w = [int.from_bytes(block64[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 80):
        w.append(rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

    a, b, c, d, e = h

    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (rol32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = rol32(b, 30)
        b = a
        a = temp

    out = (
        (h[0] + a) & 0xFFFFFFFF,
        (h[1] + b) & 0xFFFFFFFF,
        (h[2] + c) & 0xFFFFFFFF,
        (h[3] + d) & 0xFFFFFFFF,
        (h[4] + e) & 0xFFFFFFFF,
    )
    return b"".join(x.to_bytes(4, "big") for x in out)


def int160(x: bytes) -> int:
    if len(x) != 20:
        raise ValueError(f"expected 20 bytes, got {len(x)}")
    return int.from_bytes(x, "big")


def bytes160(x: int) -> bytes:
    return (x & MASK160).to_bytes(20, "big")


def fips186_gen_40_and_update(state20: bytes, aux20: bytes) -> Tuple[bytes, bytes]:
    """
    Replay the rsaenh FIPS-style block observed in the campaigns.

    Per 20-byte block:
      xval = (state20 + aux20) mod 2^160
      out20 = SHA1Compress( xval || 44 zero bytes )
      state20 = (state20 + out20 + 1) mod 2^160

    The wrapper requests two 20-byte internal blocks, yielding out40.
    """
    if len(state20) != 20:
        raise ValueError(f"state20 must be 20 bytes, got {len(state20)}")
    if len(aux20) != 20:
        raise ValueError(f"aux20 must be 20 bytes, got {len(aux20)}")

    st = state20
    outs = []

    for _ in range(2):
        xval = bytes160(int160(st) + int160(aux20))
        out20 = sha1_compress_one_block(xval + (b"\x00" * 44))
        outs.append(out20)
        st = bytes160(int160(st) + int160(out20) + 1)

    return b"".join(outs), st


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid JSONL at line {line_no}: {exc}") from exc
    return rows


def hx_to_bytes(value: str, nbytes: int, field: str, index: object) -> bytes:
    if not value:
        raise ValueError(f"call {index}: missing {field}")
    value = value[: nbytes * 2]
    if len(value) != nbytes * 2:
        raise ValueError(f"call {index}: {field} has {len(value)//2} bytes, expected {nbytes}")
    return bytes.fromhex(value)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("calls_jsonl")
    ap.add_argument("--csv")
    ap.add_argument("--jsonl")
    args = ap.parse_args()

    calls = load_jsonl(Path(args.calls_jsonl))

    rows = []
    complete = [c for c in calls if c.get("complete")]

    for pos, c in enumerate(calls):
        idx = c.get("index", pos + 1)

        row = {
            "index": idx,
            "retaddr": c.get("retaddr"),
            "complete": bool(c.get("complete")),
            "state20_before": (c.get("state20_before_fips") or "")[:40],
            "aux20": (c.get("fips_arg2_aux20") or "")[:40],
            "observed_out40": (c.get("out40_after_fips") or "")[:80],
            "replay_out40": None,
            "out40_match": None,
            "observed_state20_after": (c.get("state20_after_fips") or "")[:40],
            "replay_state20_after": None,
            "state20_after_match": None,
            "state20_after_eq_core_exit": c.get("after_fips_eq_exit"),
            "next_recurrence_match": None,
            "replay_ok": False,
            "error": None,
        }

        try:
            if c.get("complete"):
                state20 = hx_to_bytes(c.get("state20_before_fips", ""), 20, "state20_before_fips", idx)
                aux20 = hx_to_bytes(c.get("fips_arg2_aux20", ""), 20, "fips_arg2_aux20", idx)
                observed_out40 = hx_to_bytes(c.get("out40_after_fips", ""), 40, "out40_after_fips", idx)
                observed_state20_after = hx_to_bytes(c.get("state20_after_fips", ""), 20, "state20_after_fips", idx)

                replay_out40, replay_state20_after = fips186_gen_40_and_update(state20, aux20)

                row["replay_out40"] = replay_out40.hex()
                row["replay_state20_after"] = replay_state20_after.hex()
                row["out40_match"] = replay_out40 == observed_out40
                row["state20_after_match"] = replay_state20_after == observed_state20_after
                row["replay_ok"] = bool(row["out40_match"] and row["state20_after_match"])

            if pos + 1 < len(calls):
                cur_after = c.get("state20_core_exit") or c.get("state20_after_fips")
                next_before = calls[pos + 1].get("state20_core_entry")
                if cur_after and next_before:
                    row["next_recurrence_match"] = cur_after[:40] == next_before[:40]

        except Exception as exc:
            row["error"] = str(exc)

        rows.append(row)

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            fieldnames = list(rows[0].keys()) if rows else []
            w = csv.DictWriter(f, fieldnames=fieldnames)
            if rows:
                w.writeheader()
                w.writerows(rows)

    if args.jsonl:
        with open(args.jsonl, "w") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")

    complete_rows = [r for r in rows if r["complete"]]
    recurrence_rows = [r for r in rows if r["next_recurrence_match"] is not None]

    out40_ok = sum(1 for r in complete_rows if r["out40_match"] is True)
    state_ok = sum(1 for r in complete_rows if r["state20_after_match"] is True)
    exit_ok = sum(1 for r in complete_rows if r["state20_after_eq_core_exit"] is True)
    replay_ok = sum(1 for r in complete_rows if r["replay_ok"] is True)
    rec_ok = sum(1 for r in recurrence_rows if r["next_recurrence_match"] is True)

    closed = (
        len(complete_rows) > 0
        and replay_ok == len(complete_rows)
        and exit_ok == len(complete_rows)
        and rec_ok == len(recurrence_rows)
    )

    print("[V19C FIPS STATE20 UPDATE REPLAY]")
    print(f"calls={len(calls)}")
    print(f"complete_calls={len(complete_rows)}")
    print(f"out40_match={out40_ok}/{len(complete_rows)}")
    print(f"state20_after_match={state_ok}/{len(complete_rows)}")
    print(f"state20_after_eq_core_exit={exit_ok}/{len(complete_rows)}")
    print(f"recurrence_match={rec_ok}/{len(recurrence_rows)}")
    print(f"replay_ok={replay_ok}/{len(complete_rows)}")
    print()
    print("[SUMMARY]")
    print(f"v19c_provider_state_update_closed={closed}")

    failures = [r for r in rows if r.get("error") or (r["complete"] and not r["replay_ok"])]
    if failures:
        print()
        print("[FAILURES]")
        for r in failures:
            print(f"call#{r['index']} retaddr={r['retaddr']} error={r['error']} out40_match={r['out40_match']} state20_after_match={r['state20_after_match']}")


if __name__ == "__main__":
    main()
