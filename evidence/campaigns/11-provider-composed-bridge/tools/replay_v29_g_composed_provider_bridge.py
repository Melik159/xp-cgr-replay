#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def hx(b: bytes) -> str:
    return b.hex(" ")


def load_blob(sample_dir: Path, name: str) -> bytes:
    p = sample_dir / "blobs" / name
    if not p.exists():
        raise FileNotFoundError(p)
    return p.read_bytes()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def add160_be(a: bytes, b: bytes, carry: int = 0) -> bytes:
    if len(a) != 20 or len(b) != 20:
        raise ValueError("add160 requires 20-byte operands")
    n = (int.from_bytes(a, "big") + int.from_bytes(b, "big") + carry) % (1 << 160)
    return n.to_bytes(20, "big")


def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1_compress_single_block(block64: bytes) -> bytes:
    if len(block64) != 64:
        raise ValueError("SHA-1 compression requires exactly 64 bytes")

    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    w = [int.from_bytes(block64[i:i + 4], "big") for i in range(0, 64, 4)]
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

        temp = (rol32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = rol32(b, 30)
        b = a
        a = temp

    out = [
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
    ]

    return b"".join(x.to_bytes(4, "big") for x in out)


def fips_provider_block(state20_before: bytes, aux20: bytes) -> dict[str, bytes]:
    xval_a = add160_be(state20_before, aux20, 0)
    out20_a = sha1_compress_single_block(xval_a + b"\x00" * 44)
    state_a = add160_be(state20_before, out20_a, 1)

    xval_b = add160_be(state_a, aux20, 0)
    out20_b = sha1_compress_single_block(xval_b + b"\x00" * 44)
    state20_after = add160_be(state_a, out20_b, 1)

    return {
        "xval_A": xval_a,
        "out20_A": out20_a,
        "state_A": state_a,
        "xval_B": xval_b,
        "out20_B": out20_b,
        "out40": out20_a + out20_b,
        "state20_after": state20_after,
    }


def load_transition(sample_dir: Path, label: str) -> dict[str, bytes]:
    return {
        "state20_before": load_blob(sample_dir, f"{label}_state20_before.bin"),
        "sysfunc036_raw20": load_blob(sample_dir, f"{label}_sysfunc036_raw20.bin"),
        "outbuf_prefix20": load_blob(sample_dir, f"{label}_outbuf_prefix20.bin"),
        "aux20_final": load_blob(sample_dir, f"{label}_aux20_final.bin"),
        "out40": load_blob(sample_dir, f"{label}_out40.bin"),
        "state20_after": load_blob(sample_dir, f"{label}_state20_after.bin"),
    }


def check(name: str, obs: bytes, calc: bytes, results: dict[str, bool]) -> None:
    ok = obs == calc
    results[name] = ok
    print(f"[{name}] {'PASS' if ok else 'FAIL'}")
    print(f"  obs  = {hx(obs)}")
    print(f"  calc = {hx(calc)}")


def replay_transition(label: str, tr: dict[str, bytes], results: dict[str, bool]) -> dict[str, bytes]:
    aux_calc = xor_bytes(tr["sysfunc036_raw20"], tr["outbuf_prefix20"])
    calc = fips_provider_block(tr["state20_before"], aux_calc)

    print(f"\n[OBSERVED_{label.upper()}]")
    print(f"  {label}_state20_before    = {hx(tr['state20_before'])}")
    print(f"  {label}_sysfunc036_raw20  = {hx(tr['sysfunc036_raw20'])}")
    print(f"  {label}_outbuf_prefix20   = {hx(tr['outbuf_prefix20'])}")
    print(f"  {label}_aux20_final_obs   = {hx(tr['aux20_final'])}")
    print(f"  {label}_out40_obs         = {hx(tr['out40'])}")
    print(f"  {label}_state20_after_obs = {hx(tr['state20_after'])}")

    print(f"\n[CALCULATED_{label.upper()}]")
    print(f"  {label}_aux20_final_calc  = {label}_sysfunc036_raw20 XOR {label}_outbuf_prefix20")
    print(f"                            = {hx(aux_calc)}")
    print(f"  {label}_xval_A            = {hx(calc['xval_A'])}")
    print(f"  {label}_out20_A           = {hx(calc['out20_A'])}")
    print(f"  {label}_state_A           = {hx(calc['state_A'])}")
    print(f"  {label}_xval_B            = {hx(calc['xval_B'])}")
    print(f"  {label}_out20_B           = {hx(calc['out20_B'])}")
    print(f"  {label}_out40_calc        = {hx(calc['out40'])}")
    print(f"  {label}_state20_after_calc= {hx(calc['state20_after'])}")

    print()
    check(f"{label}_aux20_final", tr["aux20_final"], aux_calc, results)
    check(f"{label}_out40", tr["out40"], calc["out40"], results)
    check(f"{label}_state20_after", tr["state20_after"], calc["state20_after"], results)

    return {
        "aux20_final_calc": aux_calc,
        **calc,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_dir", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    sample_dir = args.sample_dir

    init = load_transition(sample_dir, "init")
    bridge00 = load_transition(sample_dir, "bridge00")
    runtime = load_transition(sample_dir, "runtime")
    cgr_output32 = load_blob(sample_dir, "cgr_output32.bin")

    results: dict[str, bool] = {}

    print("[V29_G_COMPOSED_PROVIDER_BRIDGE_REPLAY]")
    print(f"sample_dir={sample_dir}")

    init_calc = replay_transition("init", init, results)

    print()
    check(
        "state_continuity_init_to_bridge00",
        bridge00["state20_before"],
        init["state20_after"],
        results,
    )

    bridge_calc = replay_transition("bridge00", bridge00, results)

    print()
    check(
        "state_continuity_bridge00_to_runtime",
        runtime["state20_before"],
        bridge00["state20_after"],
        results,
    )

    runtime_calc = replay_transition("runtime", runtime, results)

    print("\n[OBSERVED_CGR]")
    print(f"  cgr_output32_obs  = {hx(cgr_output32)}")
    print("[CALCULATED_CGR]")
    print(f"  cgr_output32_calc = runtime_out40_calc[:32]")
    print(f"                    = {hx(runtime_calc['out40'][:32])}")

    print()
    check("cgr_output32", cgr_output32, runtime_calc["out40"][:32], results)

    mapping = {
        "init_aux20_final_calc_equals_observed": results["init_aux20_final"],
        "init_out40_calc_equals_observed": results["init_out40"],
        "init_state20_after_calc_equals_observed": results["init_state20_after"],
        "state_continuity_init_to_bridge00": results["state_continuity_init_to_bridge00"],
        "bridge00_aux20_final_calc_equals_observed": results["bridge00_aux20_final"],
        "bridge00_out40_calc_equals_observed": results["bridge00_out40"],
        "bridge00_state20_after_calc_equals_observed": results["bridge00_state20_after"],
        "state_continuity_bridge00_to_runtime": results["state_continuity_bridge00_to_runtime"],
        "runtime_aux20_final_calc_equals_observed": results["runtime_aux20_final"],
        "runtime_out40_calc_equals_observed": results["runtime_out40"],
        "runtime_state20_after_calc_equals_observed": results["runtime_state20_after"],
        "cgr_output32_equals_runtime_out40_prefix": results["cgr_output32"],
    }

    overall = all(mapping.values())

    print()
    for k, v in mapping.items():
        print(f"{k:<52} {'PASS' if v else 'FAIL'}")
    print(f"OVERALL={'PASS' if overall else 'FAIL'}")

    report = {
        "campaign": "seed2state_v29_g_composed_provider_bridge",
        "model": "G_provider = G_init + G_acquire_bridge_00 + G_runtime_measured",
        "checks": mapping,
        "overall": overall,
        "observed": {
            "init_state20_before": init["state20_before"].hex(),
            "init_state20_after": init["state20_after"].hex(),
            "bridge00_state20_before": bridge00["state20_before"].hex(),
            "bridge00_state20_after": bridge00["state20_after"].hex(),
            "runtime_state20_before": runtime["state20_before"].hex(),
            "runtime_state20_after": runtime["state20_after"].hex(),
            "cgr_output32": cgr_output32.hex(),
        },
        "calculated": {
            "init_out40": init_calc["out40"].hex(),
            "init_state20_after": init_calc["state20_after"].hex(),
            "bridge00_out40": bridge_calc["out40"].hex(),
            "bridge00_state20_after": bridge_calc["state20_after"].hex(),
            "runtime_out40": runtime_calc["out40"].hex(),
            "runtime_state20_after": runtime_calc["state20_after"].hex(),
            "cgr_output32": runtime_calc["out40"][:32].hex(),
        },
    }

    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
