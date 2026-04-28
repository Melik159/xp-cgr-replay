#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from xp_sha1 import SHA1Context, final_ns, fmt_hex_lines, fmt_words, update_ns

MASK32 = 0xFFFFFFFF

SEED_LEN = 0x14
SEG_LEN = 0x96
SEEDBASE_LEN = 0x50
POOL_LEN = 0x258


@dataclass(frozen=True)
class StepSnapshot:
    name: str
    length: int
    state: Tuple[int, int, int, int, int]
    count_hi: int
    count_lo: int
    buffer: bytes


@dataclass(frozen=True)
class ReplayResult:
    name: str
    total_len: int
    updates: Tuple[StepSnapshot, ...]
    state_before_final: Tuple[int, int, int, int, int]
    count_hi_before_final: int
    count_lo_before_final: int
    buffer_before_final: bytes
    pad_bytes: bytes
    state_after_final: Tuple[int, int, int, int, int]
    digest: bytes


def load_bin(path: Path) -> bytes:
    return path.read_bytes()


def split_seedbase(seedbase: bytes) -> Dict[str, bytes]:
    if len(seedbase) != SEEDBASE_LEN:
        raise ValueError(
            f"seedbase_before must be 0x{SEEDBASE_LEN:x} bytes, got 0x{len(seedbase):x}"
        )
    return {
        "seed0": seedbase[0x00:0x14],
        "seed1": seedbase[0x14:0x28],
        "seed2": seedbase[0x28:0x3C],
        "seed3": seedbase[0x3C:0x50],
    }


def split_pool(pool: bytes) -> Dict[str, bytes]:
    if len(pool) != POOL_LEN:
        raise ValueError(f"pool must be 0x{POOL_LEN:x} bytes, got 0x{len(pool):x}")
    return {
        "S0": pool[0x000:0x096],
        "S1": pool[0x096:0x12C],
        "S2": pool[0x12C:0x1C2],
        "S3": pool[0x1C2:0x258],
    }


def load_seeds_from_dir(base: Path) -> Dict[str, bytes]:
    seeds = {
        "seed0": load_bin(base / "seed0_before.bin"),
        "seed1": load_bin(base / "seed1_before.bin"),
        "seed2": load_bin(base / "seed2_before.bin"),
        "seed3": load_bin(base / "seed3_before.bin"),
    }
    for name, data in seeds.items():
        if len(data) != SEED_LEN:
            raise ValueError(f"{name} must be 0x{SEED_LEN:x} bytes, got 0x{len(data):x}")
    return seeds


def load_segments_from_dir(base: Path) -> Dict[str, bytes]:
    segs = {
        "S0": load_bin(base / "s0.bin"),
        "S1": load_bin(base / "s1.bin"),
        "S2": load_bin(base / "s2.bin"),
        "S3": load_bin(base / "s3.bin"),
    }
    for name, data in segs.items():
        if len(data) != SEG_LEN:
            raise ValueError(f"{name} must be 0x{SEG_LEN:x} bytes, got 0x{len(data):x}")
    return segs


def assert_component_sizes(
    seeds: Mapping[str, bytes],
    segments: Mapping[str, bytes],
) -> None:
    for name in ("seed0", "seed1", "seed2", "seed3"):
        data = seeds[name]
        if len(data) != SEED_LEN:
            raise ValueError(f"{name} must be 0x{SEED_LEN:x} bytes, got 0x{len(data):x}")

    for name in ("S0", "S1", "S2", "S3"):
        data = segments[name]
        if len(data) != SEG_LEN:
            raise ValueError(f"{name} must be 0x{SEG_LEN:x} bytes, got 0x{len(data):x}")


def replay_ns(name: str, updates: Sequence[Tuple[str, bytes]]) -> ReplayResult:
    ctx = SHA1Context()

    snapshots: List[StepSnapshot] = []
    total_len = 0

    for upd_name, upd_data in updates:
        update_ns(ctx, upd_data)
        total_len += len(upd_data)
        snapshots.append(
            StepSnapshot(
                name=upd_name,
                length=len(upd_data),
                state=tuple(ctx.state),
                count_hi=ctx.count_hi,
                count_lo=ctx.count_lo,
                buffer=bytes(ctx.buffer),
            )
        )

    state_before_final = tuple(ctx.state)
    count_hi_before_final = ctx.count_hi
    count_lo_before_final = ctx.count_lo
    buffer_before_final = bytes(ctx.buffer)

    state_after_final, pad_bytes, digest = final_ns(ctx)

    return ReplayResult(
        name=name,
        total_len=total_len,
        updates=tuple(snapshots),
        state_before_final=state_before_final,
        count_hi_before_final=count_hi_before_final,
        count_lo_before_final=count_lo_before_final,
        buffer_before_final=buffer_before_final,
        pad_bytes=pad_bytes,
        state_after_final=tuple(state_after_final),
        digest=digest,
    )


def build_cycle_inputs(
    seeds: Mapping[str, bytes],
    segments: Mapping[str, bytes],
) -> Dict[str, List[Tuple[str, bytes]]]:
    assert_component_sizes(seeds, segments)

    return {
        "cycle1_L0": [
            ("seed0", seeds["seed0"]),
            ("S0", segments["S0"]),
            ("seed1", seeds["seed1"]),
            ("S1", segments["S1"]),
        ],
        "cycle2_L1": [
            ("seed1", seeds["seed1"]),
            ("S1", segments["S1"]),
            ("seed0", seeds["seed0"]),
            ("S0", segments["S0"]),
        ],
        "cycle3_L2": [
            ("seed2", seeds["seed2"]),
            ("S2", segments["S2"]),
            ("seed3", seeds["seed3"]),
            ("S3", segments["S3"]),
        ],
        "cycle4_L3": [
            ("seed3", seeds["seed3"]),
            ("S3", segments["S3"]),
            ("seed2", seeds["seed2"]),
            ("S2", segments["S2"]),
        ],
    }


def build_seedprime_inputs(
    digests: Mapping[str, bytes],
) -> Dict[str, List[Tuple[str, bytes]]]:
    required = ("L0", "L1", "L2", "L3")
    for name in required:
        if name not in digests:
            raise ValueError(f"missing digest {name}")

    return {
        "seed0prime": [
            ("L0", digests["L0"]),
            ("L2", digests["L2"]),
        ],
        "seed1prime": [
            ("L1", digests["L1"]),
            ("L3", digests["L3"]),
        ],
        "seed2prime": [
            ("L2", digests["L2"]),
            ("L0", digests["L0"]),
        ],
        "seed3prime": [
            ("L3", digests["L3"]),
            ("L1", digests["L1"]),
        ],
    }

def run_vlh_core( seeds: Mapping[str, bytes], segments: Mapping[str, bytes],
) -> Tuple[Dict[str, ReplayResult], Dict[str, ReplayResult]]:
    cycle_inputs = build_cycle_inputs(seeds, segments)

    cycle_results: Dict[str, ReplayResult] = {}
    digest_map: Dict[str, bytes] = {}

    for case_name, updates in cycle_inputs.items():
        result = replay_ns(case_name, updates)
        cycle_results[case_name] = result

        if case_name.endswith("_L0"):
            digest_map["L0"] = result.digest
        elif case_name.endswith("_L1"):
            digest_map["L1"] = result.digest
        elif case_name.endswith("_L2"):
            digest_map["L2"] = result.digest
        elif case_name.endswith("_L3"):
            digest_map["L3"] = result.digest
        else:
            raise ValueError(f"unexpected cycle case name: {case_name}")

    seedprime_inputs = build_seedprime_inputs(digest_map)

    seedprime_results: Dict[str, ReplayResult] = {}
    for case_name, updates in seedprime_inputs.items():
        seedprime_results[case_name] = replay_ns(case_name, updates)

    return cycle_results, seedprime_results


def print_result(result: ReplayResult) -> None:
    print(f"=== CASE: {result.name} ===")
    for snap in result.updates:
        print(f"{snap.name:>12} : len=0x{snap.length:x}")
    print(f"{'TOTAL':>12} : len=0x{result.total_len:x}")
    print()
    print("mode: ns_candidate")
    print()

    for snap in result.updates:
        print(f"=== AFTER {snap.name} ===")
        print(f"state : {fmt_words(snap.state)}")
        print(f"count_hi={snap.count_hi:08x} count_lo={snap.count_lo:08x}")
        print(fmt_hex_lines(snap.buffer))
        print()

    print("=== BEFORE FINAL ===")
    print(f"state_calc : {fmt_words(result.state_before_final)}")
    print(
        f"count_calc : hi={result.count_hi_before_final:08x} "
        f"lo={result.count_lo_before_final:08x}"
    )
    print()

    print("=== FINAL ===")
    print("pad_bytes:")
    print(fmt_hex_lines(result.pad_bytes))
    print(f"state_after_calc : {fmt_words(result.state_after_final)}")
    print(f"digest_calc      : {result.digest.hex()}")
    print()


def results_to_json(
    cycle_results: Mapping[str, ReplayResult],
    seedprime_results: Mapping[str, ReplayResult],
) -> Dict[str, object]:
    def encode_result(r: ReplayResult) -> Dict[str, object]:
        return {
            "name": r.name,
            "total_len": r.total_len,
            "updates": [
                {
                    "name": s.name,
                    "length": s.length,
                    "state": [f"{x:08x}" for x in s.state],
                    "count_hi": f"{s.count_hi:08x}",
                    "count_lo": f"{s.count_lo:08x}",
                    "buffer_hex": s.buffer.hex(),
                }
                for s in r.updates
            ],
            "state_before_final": [f"{x:08x}" for x in r.state_before_final],
            "count_hi_before_final": f"{r.count_hi_before_final:08x}",
            "count_lo_before_final": f"{r.count_lo_before_final:08x}",
            "buffer_before_final_hex": r.buffer_before_final.hex(),
            "pad_hex": r.pad_bytes.hex(),
            "state_after_final": [f"{x:08x}" for x in r.state_after_final],
            "digest_hex": r.digest.hex(),
        }

    return {
        "cycles": {k: encode_result(v) for k, v in cycle_results.items()},
        "seedprimes": {k: encode_result(v) for k, v in seedprime_results.items()},
    }


def write_outputs(
    out_dir: Path,
    cycle_results: Mapping[str, ReplayResult],
    seedprime_results: Mapping[str, ReplayResult],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    digest_aliases = {
        "cycle1_L0": "L0.bin",
        "cycle2_L1": "L1.bin",
        "cycle3_L2": "L2.bin",
        "cycle4_L3": "L3.bin",
        "seed0prime": "seed0prime.bin",
        "seed1prime": "seed1prime.bin",
        "seed2prime": "seed2prime.bin",
        "seed3prime": "seed3prime.bin",
    }

    for name, result in cycle_results.items():
        out_path = out_dir / digest_aliases[name]
        out_path.write_bytes(result.digest)

    for name, result in seedprime_results.items():
        out_path = out_dir / digest_aliases[name]
        out_path.write_bytes(result.digest)

    summary = results_to_json(cycle_results, seedprime_results)
    (out_dir / "vlh_results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the validated VLH SHA-1 core from explicit seeds and segments."
    )
    parser.add_argument("--camp-dir", type=Path, help="Directory containing s0..s3 and seed0_before..seed3_before")
    parser.add_argument("--seed0", type=Path, help="Path to seed0_before.bin")
    parser.add_argument("--seed1", type=Path, help="Path to seed1_before.bin")
    parser.add_argument("--seed2", type=Path, help="Path to seed2_before.bin")
    parser.add_argument("--seed3", type=Path, help="Path to seed3_before.bin")
    parser.add_argument("--s0", type=Path, help="Path to s0.bin")
    parser.add_argument("--s1", type=Path, help="Path to s1.bin")
    parser.add_argument("--s2", type=Path, help="Path to s2.bin")
    parser.add_argument("--s3", type=Path, help="Path to s3.bin")
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    parser.add_argument("--out-dir", type=Path, help="Write L0..L3 and seedprime outputs to this directory")
    args = parser.parse_args()

    if args.camp_dir is not None:
        seeds = load_seeds_from_dir(args.camp_dir)
        segments = load_segments_from_dir(args.camp_dir)
    else:
        required = {
            "seed0": args.seed0,
            "seed1": args.seed1,
            "seed2": args.seed2,
            "seed3": args.seed3,
            "S0": args.s0,
            "S1": args.s1,
            "S2": args.s2,
            "S3": args.s3,
        }
        missing = [name for name, path in required.items() if path is None]
        if missing:
            parser.error(
                "missing explicit inputs: " + ", ".join(missing) +
                " (or provide --camp-dir)"
            )

        seeds = {
            "seed0": load_bin(args.seed0),
            "seed1": load_bin(args.seed1),
            "seed2": load_bin(args.seed2),
            "seed3": load_bin(args.seed3),
        }
        segments = {
            "S0": load_bin(args.s0),
            "S1": load_bin(args.s1),
            "S2": load_bin(args.s2),
            "S3": load_bin(args.s3),
        }

    cycle_results, seedprime_results = run_vlh_core(seeds, segments)

    if args.out_dir is not None:
        write_outputs(args.out_dir, cycle_results, seedprime_results)

    if args.json:
        print(json.dumps(results_to_json(cycle_results, seedprime_results), indent=2))
    else:
        for name in ("cycle1_L0", "cycle2_L1", "cycle3_L2", "cycle4_L3"):
            print_result(cycle_results[name])
        for name in ("seed1prime", "seed2prime", "seed3prime"):
            print_result(seedprime_results[name])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
