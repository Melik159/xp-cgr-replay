from __future__ import annotations

import argparse
import json
from pathlib import Path

from .checks import BLOCKS
from .common import Outcome, ValidationError


def run(selected: list[str] | None = None) -> tuple[list[dict], bool]:
    names = selected or list(BLOCKS)
    unknown = [name for name in names if name not in BLOCKS]
    if unknown:
        raise ValidationError(f"unknown block(s): {', '.join(unknown)}")

    records: list[dict] = []
    failed = False
    for block_name in names:
        title, checks = BLOCKS[block_name]
        print(f"\n[{block_name}] {title}")
        for check in checks:
            try:
                outcome: Outcome = check()
                print(f"  {outcome.status:<7} {outcome.name}: {outcome.detail}")
                records.append({
                    "block": block_name,
                    "check": outcome.name,
                    "status": outcome.status,
                    "detail": outcome.detail,
                })
            except Exception as exc:
                failed = True
                print(f"  FAIL    {check.__name__}: {exc}")
                records.append({
                    "block": block_name,
                    "check": check.__name__,
                    "status": "FAIL",
                    "detail": str(exc),
                })

    passed = sum(record["status"] == "PASS" for record in records)
    partial = sum(record["status"] == "PARTIAL" for record in records)
    failures = sum(record["status"] == "FAIL" for record in records)
    print("\n[SUMMARY]")
    print(f"PASS={passed} PARTIAL={partial} FAIL={failures}")
    print(f"OVERALL={'FAIL' if failed else 'PASS_WITH_DECLARED_PARTIAL' if partial else 'PASS'}")
    return records, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the XP CGR artifact block by block")
    parser.add_argument("--block", action="append", choices=tuple(BLOCKS), help="validate only this block; repeatable")
    parser.add_argument("--list", action="store_true", help="list validation blocks")
    parser.add_argument("--json", type=Path, help="write a machine-readable validation report")
    args = parser.parse_args(argv)
    if args.list:
        for name, (title, _) in BLOCKS.items():
            print(f"{name}: {title}")
        return 0
    records, ok = run(args.block)
    if args.json:
        args.json.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if ok else 1

