#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Optional


def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1_compress_one_block(block: bytes) -> bytes:
    if len(block) != 64:
        raise ValueError("SHA1 compression block must be exactly 64 bytes")

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

    a, b, c, d, e = h0, h1, h2, h3, h4

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

        t = (rol32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = rol32(b, 30)
        b = a
        a = t

    return struct.pack(
        ">5I",
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
    )


def add160_be(a: bytes, b: bytes, carry: int = 0) -> bytes:
    if len(a) != 20 or len(b) != 20:
        raise ValueError("add160_be expects 20-byte operands")

    n = int.from_bytes(a, "big")
    m = int.from_bytes(b, "big")
    return ((n + m + carry) % (1 << 160)).to_bytes(20, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor operands must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def fips186_provider_block(state20: bytes, aux20: bytes) -> dict[str, bytes]:
    if len(state20) != 20:
        raise ValueError("state20 must be 20 bytes")
    if len(aux20) != 20:
        raise ValueError("aux20 must be 20 bytes")

    xval_a = add160_be(state20, aux20, 0)
    out20_a = sha1_compress_one_block(xval_a + (b"\x00" * 44))
    state_a = add160_be(state20, out20_a, 1)

    xval_b = add160_be(state_a, aux20, 0)
    out20_b = sha1_compress_one_block(xval_b + (b"\x00" * 44))
    state_b = add160_be(state_a, out20_b, 1)

    return {
        "xval_a": xval_a,
        "out20_a": out20_a,
        "state_a": state_a,
        "xval_b": xval_b,
        "out20_b": out20_b,
        "out40": out20_a + out20_b,
        "state20_after": state_b,
    }


def load_blob(sample_dir: Path, name: str) -> bytes:
    p = sample_dir / "blobs" / f"{name}.bin"
    if not p.exists():
        raise FileNotFoundError(p)
    return p.read_bytes()


def hx(b: bytes) -> str:
    return b.hex()


def sp(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def check_line(name: str, ok: bool) -> str:
    return f"{name:<44} {'PASS' if ok else 'FAIL'}"


def obs_calc_block(name: str, obs: bytes, calc: bytes) -> list[str]:
    return [
        f"[{name}] {'PASS' if obs == calc else 'FAIL'}",
        f"  obs  = {sp(obs)}",
        f"  calc = {sp(calc)}",
    ]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_dir", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    sample_dir = args.sample_dir

    state20_before = load_blob(sample_dir, "state20_before")
    sysfunc036_raw20 = load_blob(sample_dir, "sysfunc036_raw20")
    outbuf_prefix20 = load_blob(sample_dir, "outbuf_prefix20")
    aux20_final_obs = load_blob(sample_dir, "aux20_final")
    out40_obs = load_blob(sample_dir, "out40_init")
    state20_after_obs = load_blob(sample_dir, "state20_after")

    aux20_final_calc = xor_bytes(sysfunc036_raw20, outbuf_prefix20)

    # Important: the FIPS replay must use aux20_final_calc, not aux20_final_obs.
    fips = fips186_provider_block(state20_before, aux20_final_calc)

    out40_calc = fips["out40"]
    state20_after_calc = fips["state20_after"]

    checks = {
        "aux20_final_calc_equals_observed": aux20_final_calc == aux20_final_obs,
        "out40_calc_equals_observed": out40_calc == out40_obs,
        "state20_after_calc_equals_observed": state20_after_calc == state20_after_obs,
    }

    overall = all(checks.values())

    lines: list[str] = []
    lines.append("[V28_PROVIDER_INIT_AUXMIX_REPLAY]")
    lines.append(f"sample_dir={sample_dir}")
    lines.append("")
    lines.append("[OBSERVED]")
    lines.append(f"  state20_before    = {sp(state20_before)}")
    lines.append(f"  sysfunc036_raw20  = {sp(sysfunc036_raw20)}")
    lines.append(f"  outbuf_prefix20   = {sp(outbuf_prefix20)}")
    lines.append(f"  aux20_final_obs   = {sp(aux20_final_obs)}")
    lines.append(f"  out40_obs         = {sp(out40_obs)}")
    lines.append(f"  state20_after_obs = {sp(state20_after_obs)}")
    lines.append("")
    lines.append("[CALCULATED]")
    lines.append("  aux20_final_calc  = sysfunc036_raw20 XOR outbuf_prefix20")
    lines.append(f"                    = {sp(aux20_final_calc)}")
    lines.append(f"  xval_A            = {sp(fips['xval_a'])}")
    lines.append(f"  out20_A           = {sp(fips['out20_a'])}")
    lines.append(f"  state_A           = {sp(fips['state_a'])}")
    lines.append(f"  xval_B            = {sp(fips['xval_b'])}")
    lines.append(f"  out20_B           = {sp(fips['out20_b'])}")
    lines.append(f"  out40_calc        = {sp(out40_calc)}")
    lines.append(f"  state20_after_calc= {sp(state20_after_calc)}")
    lines.append("")
    lines.extend(obs_calc_block("aux20_final", aux20_final_obs, aux20_final_calc))
    lines.extend(obs_calc_block("out40_init", out40_obs, out40_calc))
    lines.extend(obs_calc_block("state20_after", state20_after_obs, state20_after_calc))
    lines.append("")
    for name, ok in checks.items():
        lines.append(check_line(name, ok))
    lines.append(f"OVERALL={'PASS' if overall else 'FAIL'}")

    print("\n".join(lines))

    if args.json:
        report = {
            "sample_dir": str(sample_dir),
            "checks": checks,
            "overall": overall,
            "observed_hex": {
                "state20_before": hx(state20_before),
                "sysfunc036_raw20": hx(sysfunc036_raw20),
                "outbuf_prefix20": hx(outbuf_prefix20),
                "aux20_final": hx(aux20_final_obs),
                "out40_init": hx(out40_obs),
                "state20_after": hx(state20_after_obs),
            },
            "calculated_hex": {
                "aux20_final": hx(aux20_final_calc),
                "xval_a": hx(fips["xval_a"]),
                "out20_a": hx(fips["out20_a"]),
                "state_a": hx(fips["state_a"]),
                "xval_b": hx(fips["xval_b"]),
                "out20_b": hx(fips["out20_b"]),
                "out40_init": hx(out40_calc),
                "state20_after": hx(state20_after_calc),
            },
            "relations": {
                "aux20_final_calc": "sysfunc036_raw20 XOR outbuf_prefix20",
                "out40_calc": "FIPS186_provider_block(state20_before, aux20_final_calc)",
                "state20_after_calc": "FIPS186_provider_update(state20_before, aux20_final_calc)",
            },
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
