#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from vlh_core import (
    POOL_LEN,
    SEEDBASE_LEN,
    load_bin,
    run_vlh_core,
    split_pool,
    split_seedbase,
)

QSI_ORDER = ["05", "03", "07", "02", "21", "2d", "08", "17"]
CORE_QSI = ["03", "07", "02", "21", "2d"]
SEGMENTS = [("S0", 0x000, 0x096), ("S1", 0x096, 0x12C), ("S2", 0x12C, 0x1C2), ("S3", 0x1C2, 0x258)]

PREFIX_SOURCE_NAMES = (
    "pool_prefix_source20.bin",
    "prefix_source20.bin",
    "source20_prefix.bin",
    "pool0_source20.bin",
)


def fmt_range(r: Tuple[int, int]) -> str:
    return f"[0x{r[0]:x}:0x{r[1]:x})"


def offsets_to_ranges(offsets: Sequence[int]) -> List[Tuple[int, int]]:
    if not offsets:
        return []
    out: List[Tuple[int, int]] = []
    start = prev = offsets[0]
    for x in offsets[1:]:
        if x == prev + 1:
            prev = x
            continue
        out.append((start, prev + 1))
        start = prev = x
    out.append((start, prev + 1))
    return out


def find_all(haystack: bytes, needle: bytes) -> List[int]:
    if not needle or len(needle) > len(haystack):
        return []
    out: List[int] = []
    i = 0
    while True:
        j = haystack.find(needle, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1


def mark(covered: List[bool], start: int, end: int) -> None:
    for i in range(max(0, start), min(end, len(covered))):
        covered[i] = True


def bswap32x5(buf20: bytes) -> bytes:
    if len(buf20) != 20:
        raise ValueError("bswap32x5 expects 20 bytes")
    return b"".join(buf20[i:i+4][::-1] for i in range(0, 20, 4))


def load_campaign_dirs(patterns: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for pattern in patterns:
        matches = sorted(Path(p) for p in glob.glob(pattern))
        if matches:
            out.extend(matches)
        else:
            p = Path(pattern)
            if p.exists():
                out.append(p)
    seen = set()
    dedup: List[Path] = []
    for p in out:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            dedup.append(p)
    return dedup


def try_load_any(camp_dir: Path, names: Sequence[str]) -> Optional[bytes]:
    for name in names:
        p = camp_dir / name
        if p.exists():
            return load_bin(p)
    return None


def load_observed_after_files(camp_dir: Path) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    for name in ("seed0_after", "seed1_after", "seed2_after", "seed3_after", "seedbase_after"):
        p = camp_dir / f"{name}.bin"
        if p.exists():
            out[name] = load_bin(p)
    return out


def validate_seed_outputs(seedprime_results, observed_after: Dict[str, bytes]) -> Tuple[bool, List[str]]:
    mapping = [
        ("seed0prime", "seed0_after"),
        ("seed1prime", "seed1_after"),
        ("seed2prime", "seed2_after"),
        ("seed3prime", "seed3_after"),
    ]
    lines: List[str] = []
    ok_all = True
    concat = b"".join(seedprime_results[calc].digest for calc, _ in mapping)
    for calc_name, obs_name in mapping:
        calc = seedprime_results[calc_name].digest
        obs = observed_after.get(obs_name)
        ok = obs == calc if obs is not None else False
        ok_all &= ok
        lines.append(f"  {calc_name}: match={ok} calc={calc.hex()} obs={obs.hex() if obs is not None else 'missing'}")
    obs = observed_after.get("seedbase_after")
    ok = obs == concat if obs is not None else False
    ok_all &= ok
    lines.append(f"  seedbase_after: match={ok} calc={concat.hex()} obs={obs.hex() if obs is not None else 'missing'}")
    return ok_all, lines


def pool_autodetect(camp_dir: Path, pool: bytes) -> Tuple[bool, List[bool], List[str]]:
    covered = [False] * POOL_LEN
    lines: List[str] = []
    mapping_ok = True

    # Prefix: validate if an explicit source20 dump exists, otherwise record inferred source.
    src = try_load_any(camp_dir, PREFIX_SOURCE_NAMES)
    obs_prefix = pool[0:20]
    if src is not None:
        src = src[:20]
        calc = bswap32x5(src)
        ok = calc == obs_prefix
        mapping_ok &= ok
        lines.append(f"  prefix_bswap32x5: {ok} source20={src.hex()} calc={calc.hex()} obs={obs_prefix.hex()}")
    else:
        inferred = bswap32x5(obs_prefix)
        lines.append(f"  prefix_bswap32x5: inferred source20={inferred.hex()} obs={obs_prefix.hex()}")
    mark(covered, 0, 20)

    # Exact QSI occurrences: do not force offsets. This supports old and manual layouts.
    for cls in CORE_QSI:
        qpath = camp_dir / f"qsi_class_{cls}.bin"
        if not qpath.exists():
            mapping_ok = False
            lines.append(f"  qsi_{cls}: missing file")
            continue
        qsi = load_bin(qpath)
        hits = find_all(pool, qsi)
        if len(hits) == 1:
            off = hits[0]
            mark(covered, off, off + len(qsi))
            lines.append(f"  qsi_{cls}: exact at pool{fmt_range((off, off + len(qsi)))} len=0x{len(qsi):x}")
        elif len(hits) > 1:
            mapping_ok = False
            for off in hits:
                mark(covered, off, off + len(qsi))
            lines.append(f"  qsi_{cls}: ambiguous hits={','.join(hex(h) for h in hits)} len=0x{len(qsi):x}")
        else:
            mapping_ok = False
            lines.append(f"  qsi_{cls}: not found as contiguous len=0x{len(qsi):x}")

    # Large classes are often only prefix-visible in pool; scan useful prefix lengths.
    for cls, lengths in {"08": (0x18, 0x20, 0x40, 0x50), "17": (0x18, 0x20, 0x40, 0x50)}.items():
        qpath = camp_dir / f"qsi_class_{cls}.bin"
        if not qpath.exists():
            lines.append(f"  qsi_{cls}_prefix: missing file")
            continue
        qsi = load_bin(qpath)
        best: Optional[Tuple[int, int]] = None
        for length in lengths:
            if len(qsi) < length:
                continue
            hits = find_all(pool, qsi[:length])
            if hits:
                best = (length, hits[0])
                break
        if best:
            length, off = best
            mark(covered, off, off + length)
            lines.append(f"  qsi_{cls}_prefix: qsi[:0x{length:x}] at pool{fmt_range((off, off + length))}")
        else:
            lines.append(f"  qsi_{cls}_prefix: not found")

    # Pool allocator tag; mark the 16-byte metadata window around the tag.
    tag_hits = find_all(pool, b"Pool ")
    if tag_hits:
        desc = []
        for off in tag_hits:
            start = max(0, off - (off % 0x10))
            end = min(POOL_LEN, start + 0x10)
            mark(covered, start, end)
            desc.append(f"tag at 0x{off:x}, window={fmt_range((start, end))}, bytes={pool[start:end].hex()}")
        lines.append("  allocator_metadata: " + "; ".join(desc))
    else:
        lines.append("  allocator_metadata: tag 'Pool ' not found")

    # Mark stable zero/short gaps as explained padding, but keep them visible.
    for start, end in offsets_to_ranges([i for i, b in enumerate(pool) if b == 0 and not covered[i]]):
        # Only mark small gaps, not large unknown blocks.
        if end - start <= 8:
            mark(covered, start, end)
            lines.append(f"  padding_zero: pool{fmt_range((start, end))}")

    return mapping_ok, covered, lines


def print_campaign_report(camp_dir: Path) -> bool:
    pool = load_bin(camp_dir / "pool.bin")
    if len(pool) != POOL_LEN:
        raise ValueError(f"{camp_dir}: pool.bin must be 0x{POOL_LEN:x} bytes")
    seedbase_before = load_bin(camp_dir / "seedbase_before.bin")
    if len(seedbase_before) != SEEDBASE_LEN:
        raise ValueError(f"{camp_dir}: seedbase_before.bin must be 0x{SEEDBASE_LEN:x} bytes")

    print(f"[CAMPAIGN] {camp_dir}\n")
    print("[POOL AUTODETECT V3]")
    mapping_ok, covered, lines = pool_autodetect(camp_dir, pool)
    for line in lines:
        print(line)
    cov = [i for i, x in enumerate(covered) if x]
    uncov = [i for i, x in enumerate(covered) if not x]
    print(f"  explained: 0x{len(cov):x} / 0x{POOL_LEN:x} ({len(cov) / POOL_LEN:.2%})")
    print(f"  unexplained_ranges: {'none' if not uncov else ', '.join(fmt_range(r) for r in offsets_to_ranges(uncov))}")
    print(f"  MAPPING_PASS: {mapping_ok}\n")

    print("[POOL -> S]")
    segments = split_pool(pool)
    for name, _, _ in SEGMENTS:
        print(f"  {name}: len=0x{len(segments[name]):x}")
    print()

    print("[VLH / SEED VALIDATION]")
    seeds = split_seedbase(seedbase_before)
    cycle_results, seedprime_results = run_vlh_core(seeds, segments)
    print(f"  L0 : {cycle_results['cycle1_L0'].digest.hex()}")
    print(f"  L1 : {cycle_results['cycle2_L1'].digest.hex()}")
    print(f"  L2 : {cycle_results['cycle3_L2'].digest.hex()}")
    print(f"  L3 : {cycle_results['cycle4_L3'].digest.hex()}")
    observed = load_observed_after_files(camp_dir)
    if observed:
        seed_ok, seed_lines = validate_seed_outputs(seedprime_results, observed)
        for line in seed_lines:
            print(line)
    else:
        seed_ok = False
        print("  observed *_after.bin files missing")
    print(f"  SEED_PASS: {seed_ok}\n")

    ok = seed_ok and mapping_ok
    print(f"[PASS] {ok}\n")
    return ok


def main() -> int:
    p = argparse.ArgumentParser(description="Auto-detect QSI/pool mapping and validate VLH seed replay.")
    p.add_argument("camp_patterns", nargs="*", default=["camp*"], help="campaign dirs/globs")
    args = p.parse_args()
    dirs = load_campaign_dirs(args.camp_patterns)
    if not dirs:
        print("No campaign directories matched.")
        return 1
    all_ok = True
    for i, d in enumerate(dirs):
        all_ok &= print_campaign_report(d)
        if i + 1 != len(dirs):
            print("=" * 72)
    print("[GLOBAL]")
    print(f"  campaigns: {len(dirs)}")
    print(f"  PASS: {all_ok}")
    return 0 if all_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
