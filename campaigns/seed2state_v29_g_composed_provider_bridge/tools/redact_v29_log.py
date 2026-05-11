#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

DROP_PREFIXES = (
    "Opened log file",
    "Closing open log file",
    "Current expression evaluator",
)

PROMPT_RE = re.compile(r"^\d+:\s+kd>\s*")
HEX_DUMP_RE = re.compile(r"^[0-9a-fA-F]{8}\s+")
REGISTER_RE = re.compile(r"^(eax=|eip=|cs=|state=|aux_dst=|out=|phase=)")
STACK_RE = re.compile(r"^\s*#\s+ChildEBP|^WARNING:")
MARKER_RE = re.compile(r"^\[V29_")
BP_LIST_RE = re.compile(r"^\s*\d+\s+[ed]\s+(Disable|Enable)\s+Clear")


def sanitize(line: str) -> str:
    line = line.rstrip("\n")
    line = PROMPT_RE.sub("", line)
    line = re.sub(r"C:\\Temp\\[^'\"]+", r"C:\\Temp\\<redacted>", line)
    return line.rstrip()


def is_useful(line: str) -> bool:
    if not line:
        return True

    if line.startswith("bp ") or line.startswith("ba "):
        return False

    if line.strip() in {"bl", "g", "gh", "bc *"}:
        return False

    if BP_LIST_RE.match(line):
        return False

    if any(line.startswith(p) for p in DROP_PREFIXES):
        return False

    if MARKER_RE.match(line):
        return True

    if HEX_DUMP_RE.match(line):
        return True

    if REGISTER_RE.match(line):
        return True

    if STACK_RE.match(line):
        return True

    if line.startswith(("00 ", "01 ", "02 ", "03 ", "04 ", "05 ", "06 ", "07 ", "08 ", "09 ")):
        return True

    if "ChildEBP RetAddr" in line:
        return True

    if "call    6800d640" in line:
        return True

    if "call    68027101" in line:
        return True

    if "SystemFunction036" in line:
        return True

    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Redact a V29 WinDbg/KD log while keeping parser-relevant trace lines")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()

    raw_lines = args.input.read_text(errors="replace").splitlines()
    out: list[str] = []
    keep = False

    for raw in raw_lines:
        line = sanitize(raw)

        if MARKER_RE.match(line):
            keep = True
            out.append(line)
            continue

        if not keep:
            continue

        if "ntdll!DbgBreakPoint" in line:
            continue
        if "Break instruction exception" in line:
            continue
        if "Single step exception" in line:
            continue
        if "First chance exceptions" in line:
            continue

        if is_useful(line):
            out.append(line)

    collapsed: list[str] = []
    blank = False
    for line in out:
        if line == "":
            if not blank:
                collapsed.append(line)
            blank = True
        else:
            collapsed.append(line)
            blank = False

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(collapsed).rstrip() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
