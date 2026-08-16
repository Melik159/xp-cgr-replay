#!/usr/bin/env python3
"""Blind predictor: this module rejects and never opens observation fields."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from model import predict, validate_sources
from provider_state import load_state

FORBIDDEN = {"observed_output", "expected_output", "caller_output", "output_hex", "observed", "expected"}


def reject_forbidden(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN:
                raise ValueError(f"forbidden prediction input field at {location}.{key}")
            reject_forbidden(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_forbidden(child, f"{location}[{index}]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-before", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    state = load_state(args.state_before)
    sources = json.loads(args.sources.read_text(encoding="utf-8"))
    reject_forbidden(state)
    reject_forbidden(sources)
    validate_sources(sources)
    result = predict(state, sources)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PREDICT PASS boundary={state['boundary']} digest={result['input_digest_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

