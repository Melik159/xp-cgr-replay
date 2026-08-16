#!/usr/bin/env python3
"""Interactive/offline playground for the validated 32-byte XP CryptGenRandom model.

This tool never opens observed.json.  It computes a baseline from the selected
fixture, applies explicit mutations, and optionally exhaustively enumerates a
bounded byte range.

Search spec grammar (byte ranges are [start,end), end excluded):
  ksec:<event>:<source>:<start>[:<end>]
  ksec_before:<event>:<start>[:<end>]
  sys:<index>:<start>[:<end>]
  caller:<index>:<start>[:<end>]

Examples:
  --set 'ksec:0:qsi05:0=ff'
  --xor 'ksec:0:qsi17:20=01'
  --search 'ksec:0:qsi17:20:22' --results /tmp/qsi17.jsonl
  --search 'sys:2:0:2' --target-output <64 hex chars>
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from model import LAYOUT, SOURCE_SIZES, predict, validate_sources
from provider_state import load_state

DEFAULT_MAX_TRIALS = 1_000_000
FULL_BYTE_VALUES = 256


@dataclass(frozen=True)
class Target:
    kind: str
    index: int
    name: str | None
    start: int
    end: int
    captured_size: int
    effective_ranges: tuple[tuple[int, int], ...]

    @property
    def width(self) -> int:
        return self.end - self.start

    @property
    def label(self) -> str:
        if self.kind == "ksec":
            return f"ksec:{self.index}:{self.name}:{self.start}:{self.end}"
        return f"{self.kind}:{self.index}:{self.start}:{self.end}"


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    clean = sorted((a, b) for a, b in ranges if b > a)
    merged: list[list[int]] = []
    for start, end in clean:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return tuple((a, b) for a, b in merged)


def ksec_effective_ranges(name: str) -> tuple[tuple[int, int], ...]:
    if name == "allocator":
        return ((0, 8),)
    offset, payload_len, reserved_len, transform = LAYOUT[name]
    del offset
    if transform == "copy":
        return ((0, reserved_len),)
    return _merge_ranges(((0, payload_len), (20, reserved_len)))


def ranges_text(ranges: tuple[tuple[int, int], ...]) -> str:
    return ",".join(f"{a}:{b}" for a, b in ranges) or "none"


def range_is_effective(start: int, end: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    # Every searched byte must be covered by an effective range.
    for pos in range(start, end):
        if not any(a <= pos < b for a, b in ranges):
            return False
    return True


def parse_int(text: str) -> int:
    return int(text, 0)


def parse_values(text: str) -> tuple[int, int]:
    try:
        lo_s, hi_s = text.split(":", 1)
        lo, hi = parse_int(lo_s), parse_int(hi_s)
    except Exception as exc:
        raise argparse.ArgumentTypeError("--values must be MIN:MAX, e.g. 0:255 or 0x20:0x7e") from exc
    if not (0 <= lo <= hi <= 255):
        raise argparse.ArgumentTypeError("--values bounds must satisfy 0 <= MIN <= MAX <= 255")
    return lo, hi


def parse_target(spec: str, sources: dict[str, Any]) -> Target:
    parts = spec.split(":")
    kind = parts[0]
    try:
        if kind == "ksec":
            if len(parts) not in (4, 5):
                raise ValueError("ksec spec: ksec:EVENT:SOURCE:START[:END]")
            event = parse_int(parts[1])
            name = parts[2]
            start = parse_int(parts[3])
            end = parse_int(parts[4]) if len(parts) == 5 else start + 1
            if not 0 <= event < len(sources["ksec_events"]):
                raise ValueError(f"event must be 0..{len(sources['ksec_events']) - 1}")
            if name not in SOURCE_SIZES:
                raise ValueError(f"unknown KSec source {name!r}")
            size = SOURCE_SIZES[name]
            effective = ksec_effective_ranges(name)
        elif kind == "ksec_before":
            if len(parts) not in (3, 4):
                raise ValueError("ksec_before spec: ksec_before:EVENT:START[:END]")
            event = parse_int(parts[1])
            start = parse_int(parts[2])
            end = parse_int(parts[3]) if len(parts) == 4 else start + 1
            if not 0 <= event < len(sources["ksec_events"]):
                raise ValueError(f"event must be 0..{len(sources['ksec_events']) - 1}")
            name = None
            size = 256
            effective = ((0, 256),)
        elif kind == "sys":
            if len(parts) not in (3, 4):
                raise ValueError("sys spec: sys:INDEX:START[:END]")
            event = parse_int(parts[1])
            start = parse_int(parts[2])
            end = parse_int(parts[3]) if len(parts) == 4 else start + 1
            if not 0 <= event < len(sources["systemfunction_inputs_hex"]):
                raise ValueError("systemfunction index must be 0..2")
            name = None
            size = 32
            effective = ((0, 20),)
        elif kind == "caller":
            if len(parts) not in (3, 4):
                raise ValueError("caller spec: caller:INDEX:START[:END]")
            event = parse_int(parts[1])
            start = parse_int(parts[2])
            end = parse_int(parts[3]) if len(parts) == 4 else start + 1
            if not 0 <= event < len(sources["provider_calls"]):
                raise ValueError("caller index must be 0..1")
            name = None
            size = 32
            effective = ((0, min(sources["provider_calls"][event]["length"], 20)),)
        else:
            raise ValueError(f"unknown target kind {kind!r}")
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(f"invalid target {spec!r}: {exc}") from exc

    if not (0 <= start < end <= size):
        raise ValueError(f"invalid target {spec!r}: byte range must satisfy 0 <= start < end <= {size}")
    return Target(kind, event, name, start, end, size, effective)


def get_blob(sources: dict[str, Any], target: Target) -> bytes:
    if target.kind == "ksec":
        value = sources["ksec_events"][target.index]["sources"][target.name]
    elif target.kind == "ksec_before":
        value = sources["ksec_events"][target.index]["ksec_output_before_hex"]
    elif target.kind == "sys":
        value = sources["systemfunction_inputs_hex"][target.index]
    elif target.kind == "caller":
        value = sources["provider_calls"][target.index]["caller_buffer_before_hex"]
    else:  # pragma: no cover
        raise AssertionError(target.kind)
    return bytes.fromhex(value)


def set_blob(sources: dict[str, Any], target: Target, blob: bytes) -> None:
    value = blob.hex()
    if target.kind == "ksec":
        sources["ksec_events"][target.index]["sources"][target.name] = value
    elif target.kind == "ksec_before":
        sources["ksec_events"][target.index]["ksec_output_before_hex"] = value
    elif target.kind == "sys":
        sources["systemfunction_inputs_hex"][target.index] = value
    elif target.kind == "caller":
        sources["provider_calls"][target.index]["caller_buffer_before_hex"] = value
    else:  # pragma: no cover
        raise AssertionError(target.kind)


def patch_blob(sources: dict[str, Any], target: Target, replacement: bytes, xor: bool = False) -> None:
    if len(replacement) != target.width:
        raise ValueError(f"{target.label}: expected {target.width} replacement bytes, got {len(replacement)}")
    blob = bytearray(get_blob(sources, target))
    if xor:
        for i, value in enumerate(replacement, target.start):
            blob[i] ^= value
    else:
        blob[target.start:target.end] = replacement
    set_blob(sources, target, bytes(blob))


def parse_assignment(text: str, sources: dict[str, Any]) -> tuple[Target, bytes]:
    if "=" not in text:
        raise ValueError("assignment must be TARGET=HEX")
    spec, hex_value = text.split("=", 1)
    target = parse_target(spec, sources)
    try:
        value = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ValueError(f"invalid replacement hex in {text!r}") from exc
    if len(value) != target.width:
        raise ValueError(f"{target.label}: expected {target.width} bytes, got {len(value)}")
    return target, value


def hamming_hex(left: str, right: str) -> int:
    a, b = bytes.fromhex(left), bytes.fromhex(right)
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def show_bounds(sources: dict[str, Any], max_trials: int, values: tuple[int, int]) -> None:
    lo, hi = values
    cardinality = hi - lo + 1
    max_bytes = 0 if cardinality <= 1 else int(math.log(max_trials, cardinality))
    while cardinality ** (max_bytes + 1) <= max_trials:
        max_bytes += 1
    while max_bytes > 0 and cardinality ** max_bytes > max_trials:
        max_bytes -= 1

    print(f"value_domain={lo:#04x}:{hi:#04x} cardinality={cardinality} max_trials={max_trials} default_max_cartesian_bytes={max_bytes}")
    print("KSec sources (event 0..7):")
    for name, size in SOURCE_SIZES.items():
        effective = ksec_effective_ranges(name)
        print(f"  {name:10s} captured={size:4d}B effective={ranges_text(effective)} values={lo:#04x}:{hi:#04x}")
    print("Other mutable model inputs:")
    print(f"  ksec_before event=0..7 captured=256B effective=0:256 values={lo:#04x}:{hi:#04x}")
    print(f"  sys         index=0..2 captured=32B  effective=0:20  values={lo:#04x}:{hi:#04x}")
    for index, call in enumerate(sources["provider_calls"]):
        end = min(call["length"], 20)
        print(f"  caller      index={index} captured=32B  effective=0:{end} values={lo:#04x}:{hi:#04x}")
    print("Search bytes are Cartesian: trials = value_cardinality ** searched_bytes.")
    print("Examples: 1 byte over 0..255 = 256; 2 bytes = 65,536; 3 bytes = 16,777,216.")


def candidate_values(lo: int, hi: int, width: int) -> Iterable[bytes]:
    domain = range(lo, hi + 1)
    for values in itertools.product(domain, repeat=width):
        yield bytes(values)


def load_fixture(package_root: Path, run: str, boundary: str) -> tuple[dict[str, Any], dict[str, Any]]:
    run_dir = package_root / "fixtures" / run
    if not run_dir.is_dir():
        raise ValueError(f"fixture run not found: {run_dir}")
    state_name = "state_before.json" if boundary == "pre_acquisition" else "runtime_state_before.json"
    state = load_state(run_dir / state_name)
    sources = json.loads((run_dir / "sources.json").read_text(encoding="utf-8"))
    validate_sources(sources)
    return state, sources


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline 32-byte CryptGenRandom playground with bounded exhaustive search")
    parser.add_argument("--run", default="run1", choices=("run1", "run2"))
    parser.add_argument("--boundary", default="pre_acquisition", choices=("pre_acquisition", "pre_runtime"))
    parser.add_argument("--fixtures-root", type=Path, help="optional package root containing fixtures/")
    parser.add_argument("--bounds", action="store_true", help="show effective search ranges and exit")
    parser.add_argument("--set", action="append", default=[], metavar="TARGET=HEX", help="replace bytes before prediction/search")
    parser.add_argument("--xor", action="append", default=[], metavar="TARGET=HEX", help="XOR bytes before prediction/search")
    parser.add_argument("--search", metavar="TARGET", help="exhaustively enumerate TARGET byte range")
    parser.add_argument("--values", type=parse_values, default=(0, 255), metavar="MIN:MAX", help="inclusive value domain per searched byte (default 0:255)")
    parser.add_argument("--max-trials", type=int, default=DEFAULT_MAX_TRIALS, help=f"maximum Cartesian trials (default {DEFAULT_MAX_TRIALS})")
    parser.add_argument("--allow-ineffective", action="store_true", help="allow searching bytes known not to affect this model boundary")
    parser.add_argument("--target-output", help="stop on exact 32-byte output hex")
    parser.add_argument("--target-prefix", help="stop on output hex prefix")
    parser.add_argument("--results", type=Path, help="write every candidate as JSONL")
    parser.add_argument("--progress", type=int, default=10000, help="progress interval; 0 disables")
    parser.add_argument("--save-sources", type=Path, help="save sources after --set/--xor mutations")
    args = parser.parse_args()

    if args.max_trials < 1:
        parser.error("--max-trials must be >= 1")
    if args.target_output and args.target_prefix:
        parser.error("choose only one of --target-output/--target-prefix")
    if args.target_output:
        try:
            if len(bytes.fromhex(args.target_output)) != 32:
                raise ValueError
        except ValueError:
            parser.error("--target-output must be exactly 32 bytes (64 hex characters)")
        args.target_output = args.target_output.lower()
    if args.target_prefix:
        try:
            bytes.fromhex(args.target_prefix if len(args.target_prefix) % 2 == 0 else args.target_prefix + "0")
        except ValueError:
            parser.error("--target-prefix must be hexadecimal")
        args.target_prefix = args.target_prefix.lower()

    package_root = args.fixtures_root or Path(__file__).resolve().parent.parent
    try:
        state, sources = load_fixture(package_root, args.run, args.boundary)
    except ValueError as exc:
        parser.error(str(exc))

    if args.bounds:
        show_bounds(sources, args.max_trials, args.values)
        return 0

    try:
        for assignment in args.set:
            target, value = parse_assignment(assignment, sources)
            patch_blob(sources, target, value, xor=False)
        for assignment in args.xor:
            target, value = parse_assignment(assignment, sources)
            patch_blob(sources, target, value, xor=True)
        validate_sources(sources)
    except ValueError as exc:
        parser.error(str(exc))

    if args.save_sources:
        args.save_sources.write_text(json.dumps(sources, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    baseline = predict(state, copy.deepcopy(sources))
    baseline_output = baseline["predicted_output_hex"]
    print(f"run={args.run} boundary={args.boundary}")
    print(f"baseline_output={baseline_output}")

    if not args.search:
        print(f"state_after_fips={baseline['predicted_state_after']['provider_fips_state_hex']}")
        print(f"input_digest_sha256={baseline['input_digest_sha256']}")
        return 0

    try:
        target = parse_target(args.search, sources)
    except ValueError as exc:
        parser.error(str(exc))

    if args.boundary == "pre_runtime" and target.kind in ("ksec", "ksec_before"):
        parser.error("pre_runtime prediction does not consume KSec inputs; use --boundary pre_acquisition")
    if args.boundary == "pre_runtime" and target.kind == "sys" and target.index != 2:
        parser.error("pre_runtime prediction consumes only sys:2")
    if args.boundary == "pre_runtime" and target.kind == "caller" and target.index != 1:
        parser.error("pre_runtime prediction consumes only caller:1")

    effective = range_is_effective(target.start, target.end, target.effective_ranges)
    if not effective and not args.allow_ineffective:
        parser.error(f"{target.label} includes bytes outside effective range(s) {ranges_text(target.effective_ranges)}; use --allow-ineffective to override")

    lo, hi = args.values
    cardinality = hi - lo + 1
    total = cardinality ** target.width
    if total > args.max_trials:
        parser.error(
            f"search requires {total:,} trials ({cardinality}^{target.width}), above --max-trials={args.max_trials:,}; "
            f"narrow --values/byte range or raise --max-trials explicitly"
        )
    if total > 256 and not (args.results or args.target_output or args.target_prefix):
        parser.error("search >256 trials requires --results, --target-output, or --target-prefix to avoid flooding stdout")

    original_blob = get_blob(sources, target)
    result_handle = args.results.open("w", encoding="utf-8") if args.results else None
    start_time = time.monotonic()
    found: dict[str, Any] | None = None
    try:
        for trial, candidate in enumerate(candidate_values(lo, hi, target.width), 1):
            working_sources = copy.deepcopy(sources)
            blob = bytearray(original_blob)
            blob[target.start:target.end] = candidate
            set_blob(working_sources, target, bytes(blob))
            result = predict(state, working_sources)
            output = result["predicted_output_hex"]
            record = {
                "trial": trial,
                "target": target.label,
                "candidate_hex": candidate.hex(),
                "output_hex": output,
                "hamming_from_baseline": hamming_hex(baseline_output, output),
            }
            if result_handle:
                result_handle.write(json.dumps(record, sort_keys=True) + "\n")
            elif total <= 256:
                print(f"trial={trial} candidate={candidate.hex()} output={output} hamming={record['hamming_from_baseline']}")

            hit = ((args.target_output is not None and output == args.target_output) or
                   (args.target_prefix is not None and output.startswith(args.target_prefix)))
            if hit:
                found = record
                print(f"MATCH trial={trial} candidate={candidate.hex()} output={output}")
                break
            if args.progress and trial % args.progress == 0:
                elapsed = max(time.monotonic() - start_time, 1e-9)
                print(f"progress={trial}/{total} rate={trial/elapsed:.1f}/s", file=sys.stderr)
    finally:
        if result_handle:
            result_handle.close()

    elapsed = time.monotonic() - start_time
    completed = found["trial"] if found else total
    print(f"SEARCH_DONE target={target.label} trials={completed}/{total} elapsed={elapsed:.3f}s match={'YES' if found else 'NO'}")
    if args.results:
        print(f"results={args.results}")
    return 0 if (found is not None or (args.target_output is None and args.target_prefix is None)) else 2


if __name__ == "__main__":
    raise SystemExit(main())
