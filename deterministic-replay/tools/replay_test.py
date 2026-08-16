#!/usr/bin/env python3
"""Repeat the pure model and assert byte-identical canonical results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from model import canonical_hash, predict, validate_sources
from provider_state import load_state


def reverse_maps(value):
    if isinstance(value, dict):
        return {key: reverse_maps(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reverse_maps(child) for child in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--fixtures-root", type=Path,
                        default=Path(__file__).resolve().parents[1] / "fixtures")
    args = parser.parse_args()
    if args.iterations < 1:
        raise SystemExit("iterations must be positive")
    fixture = args.fixtures_root / Path(args.run).name
    state = load_state(fixture / "state_before.json")
    sources = json.loads((fixture / "sources.json").read_text(encoding="utf-8"))
    validate_sources(sources)
    baseline = predict(state, sources)
    digest = canonical_hash(baseline)
    for index in range(args.iterations):
        candidate_sources = reverse_maps(sources) if index % 2 else sources
        candidate = predict(state, candidate_sources)
        if canonical_hash(candidate) != digest or candidate != baseline:
            print(f"REPLAY FAIL iteration={index}")
            return 1
    code = "\n".join((Path(__file__).with_name(name).read_text(encoding="utf-8")
                       for name in ("model.py", "predict_cgr.py")))
    forbidden = ("/dev/random", "/dev/urandom", "os.environ", "import random", "import time")
    hits = [token for token in forbidden if token in code]
    if hits:
        print(f"REPLAY FAIL forbidden_dependencies={hits}")
        return 1
    print(f"REPLAY PASS run={Path(args.run).name} iterations={args.iterations} digest={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
