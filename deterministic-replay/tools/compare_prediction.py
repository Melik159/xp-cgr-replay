#!/usr/bin/env python3
"""Reveal phase: compare a sealed prediction with an observation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def first_byte_difference(left: str, right: str) -> tuple[int | None, str, str]:
    a, b = bytes.fromhex(left), bytes.fromhex(right)
    for index, (got, expected) in enumerate(zip(a, b)):
        if got != expected:
            return index, f"{got:02x}", f"{expected:02x}"
    if len(a) != len(b):
        return min(len(a), len(b)), "EOF" if len(a) < len(b) else f"{a[len(b)]:02x}", "EOF" if len(b) < len(a) else f"{b[len(a)]:02x}"
    return None, "", ""


def compare_value(got: Any, expected: Any, path: str) -> str | None:
    if isinstance(got, dict) and isinstance(expected, dict):
        if set(got) != set(expected):
            return f"{path}: fields got={sorted(got)} expected={sorted(expected)}"
        for key in sorted(got):
            error = compare_value(got[key], expected[key], f"{path}.{key}")
            if error:
                return error
        return None
    if isinstance(got, list) and isinstance(expected, list):
        if len(got) != len(expected):
            return f"{path}: length got={len(got)} expected={len(expected)}"
        for index, (left, right) in enumerate(zip(got, expected)):
            error = compare_value(left, right, f"{path}[{index}]")
            if error:
                return error
        return None
    if got != expected:
        if path.endswith("_hex") and isinstance(got, str) and isinstance(expected, str):
            offset, got_byte, expected_byte = first_byte_difference(got, expected)
            return f"{path}: offset={offset} got={got_byte} expected={expected_byte}"
        return f"{path}: got={got!r} expected={expected!r}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("prediction", type=Path)
    parser.add_argument("observed", type=Path)
    args = parser.parse_args()
    prediction = json.loads(args.prediction.read_text(encoding="utf-8"))
    observed = json.loads(args.observed.read_text(encoding="utf-8"))
    error = compare_value(prediction.get("predicted_output_hex"), observed.get("output_hex"), "output_hex")
    if not error:
        error = compare_value(prediction.get("predicted_state_after"), observed.get("state_after"), "state_after")
    if error:
        print(f"COMPARE FAIL {error}")
        return 1
    print("COMPARE PASS output=equal state_after=equal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

