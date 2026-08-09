#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

KEEP_MARKERS = [
    "[GSTATE_INIT_CALL_680120CF_BEFORE_SUB_6800D640]",
    "[GSTATE_INIT_AUX_BEFORE_SYSTEMFUNCTION036_6800D693]",
    "[GSTATE_INIT_AUX_AFTER_SYSTEMFUNCTION036_6800D69E]",
    "[GSTATE_INIT_FIPS_ENTRY_68027101]",
    "[GSTATE_INIT_RETURN_680120D4_AFTER_SUB_6800D640]",
]

DROP_PREFIXES = (
    "Opened log file",
    "Closing open log file",
    "Current expression evaluator",
)

PROMPT_RE = re.compile(r"^\d+:\s+kd>\s*")
HEX_DUMP_RE = re.compile(r"^[0-9a-fA-F]{8}\s+")
REGISTER_RE = re.compile(r"^(eax=|eip=|cs=|001b:|state=|aux_dst=)")
STACK_RE = re.compile(r"^\s*#\s+ChildEBP|^WARNING:")
DISASM_RE = re.compile(r"^[0-9a-fA-F]{8}\s+[0-9a-fA-F]{2}")
MARKER_RE = re.compile(r"^\[GSTATE_INIT_")

def sanitize(line: str) -> str:
    line = line.rstrip("\n")

    # Remove WinDbg prompts but keep the useful command/output when relevant.
    line = PROMPT_RE.sub("", line)

    # Remove local Windows temp paths if they appear.
    line = re.sub(r"C:\\Temp\\[^'\"]+", r"C:\\Temp\\<redacted>", line)

    return line.rstrip()

def is_useful(line: str) -> bool:
    if not line:
        return True

    # Drop WinDbg command/setup noise.
    if line.startswith("bp "):
        return False

    if line.strip() in {"bl", "g", "bc *"}:
        return False

    # Drop breakpoint list lines.
    if re.match(r"^\s*\d+\s+[ed]\s+(Disable|Enable)\s+Clear", line):
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

    if line.startswith("00 ") or line.startswith("01 ") or line.startswith("02 ") or line.startswith("03 "):
        return True

    if "ChildEBP RetAddr" in line:
        return True

    if line.startswith("state=") or line.startswith("aux_dst="):
        return True

    if "call    6800d640" in line:
        return True

    if "call    68027101" in line:
        return True

    if "SystemFunction036" in line:
        return True

    return False

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()

    raw_lines = args.input.read_text(errors="replace").splitlines()

    out: list[str] = []
    keep = False

    for raw in raw_lines:
        line = sanitize(raw)

        if any(m in line for m in KEEP_MARKERS):
            keep = True
            out.append(line)
            continue

        if keep and MARKER_RE.match(line):
            out.append(line)
            continue

        if keep:
            # Stop after the final marker block when later DebugBreak noise begins.
            if "ntdll!DbgBreakPoint" in line:
                continue
            if "Break instruction exception" in line:
                continue
            if is_useful(line):
                out.append(line)

    # Collapse excessive blank lines.
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
