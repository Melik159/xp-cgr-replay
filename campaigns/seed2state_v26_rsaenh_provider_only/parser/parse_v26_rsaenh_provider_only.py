#!/usr/bin/env python3
# parser/parse_v26_rsaenh_provider_only.py
#
# V26 rsaenh provider-only parser.
#
# Goal:
#   Validate the local rsaenh provider transition:
#
#     state20 @ 68031958
#     + aux20 local
#     -> fips186rng_gen_block
#     -> out40 local
#     -> out40[:len] copied to caller buffer
#     -> state20 slot updated by FIPS update helper
#
# This parser is deliberately verbose. It does not just say PASS/FAIL;
# it prints the reason, markers, line numbers, compared bytes, and failure cause.

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


MARK_RE = re.compile(r"^\[([A-Z0-9_]+)\]\s*$")
REG_RE = re.compile(r"\b([a-z]{2,3})=([0-9a-fA-F]{8})")
DB_RE = re.compile(r"^\s*([0-9a-fA-F]{8})\s+(.+)$")
EVAL_RE = re.compile(r"Evaluate expression:\s+(-?\d+)\s+=\s+([0-9a-fA-F`]+)")


MAJOR_MARKERS = {
    "V26_SELFTEST_STATIC_COPY_68011CA3",
    "V26_SELFTEST_AFTER_D640_68011CAA",
    "V26_D640_ENTRY_6800D640",
    "V26_SOURCE_TO_STATE20_SLOT_COPY_6800D677",
    "V26_AFTER_SOURCE_COPY_OR_NULL_6800D679",
    "V26_BEFORE_FIPS_CALL_6800D6F6",
    "V26_FIPS_ENTRY_68027101",
    "V26_FIPS_UPDATE_A_RETURN_680271D5",
    "V26_FIPS_UPDATE_B_RETURN_68027297",
    "V26_AFTER_FIPS_CALL_6800D6FB",
    "V26_BEFORE_OUT_COPY_6800D70E",
    "V26_AFTER_OUT_COPY_6800D713",
    "V26_D640_RETURN_6800D743",
}


@dataclass
class DbBlob:
    line: int
    addr: int
    data: bytes


@dataclass
class Event:
    marker: str
    line: int
    text: List[str] = field(default_factory=list)
    regs: Dict[str, int] = field(default_factory=dict)
    db_blobs: List[DbBlob] = field(default_factory=list)
    evals: List[Tuple[int, int]] = field(default_factory=list)


def hexbytes(b: bytes, max_len: int = 64) -> str:
    if not b:
        return "<missing>"
    shown = b[:max_len].hex()
    return " ".join(shown[i:i + 2] for i in range(0, len(shown), 2))


def parse_db_line(line_no: int, line: str) -> Optional[DbBlob]:
    m = DB_RE.match(line)
    if not m:
        return None

    addr = int(m.group(1), 16)

    # WinDbg db format:
    #   68031958  aa bb cc dd-ee ff ...  ASCII
    #
    # We keep only the hex-byte zone. The ASCII column is separated by
    # two spaces in normal output. The dash after 8 bytes is removed.
    rest = m.group(2).split("  ")[0].replace("-", " ")

    out: List[int] = []
    for tok in rest.split():
        if re.fullmatch(r"[0-9a-fA-F]{2}", tok):
            out.append(int(tok, 16))

    if not out:
        return None

    return DbBlob(line=line_no, addr=addr, data=bytes(out))


def parse_regs(line: str) -> Dict[str, int]:
    return {k: int(v, 16) for k, v in REG_RE.findall(line)}


def parse_eval(line: str) -> Optional[Tuple[int, int]]:
    m = EVAL_RE.search(line)
    if not m:
        return None

    dec_value = int(m.group(1), 10)
    hex_txt = m.group(2).replace("`", "")
    hex_value = int(hex_txt, 16)
    return dec_value, hex_value


def collect_events(lines: List[str]) -> List[Event]:
    events: List[Event] = []
    current: Optional[Event] = None

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        m = MARK_RE.match(line.strip())

        if m:
            current = Event(marker=m.group(1), line=idx)
            events.append(current)
            continue

        if current is None:
            continue

        current.text.append(line)

        regs = parse_regs(line)
        if regs:
            current.regs.update(regs)

        db = parse_db_line(idx, line)
        if db is not None:
            current.db_blobs.append(db)

        ev = parse_eval(line)
        if ev is not None:
            current.evals.append(ev)

    return events


def first_event(events: List[Event], marker: str, start: int = 0, stop: Optional[int] = None) -> Optional[Event]:
    if stop is None:
        stop = len(events)

    for i in range(start, min(stop, len(events))):
        if events[i].marker == marker:
            return events[i]

    return None


def event_indices(events: List[Event], marker: str) -> List[int]:
    return [i for i, e in enumerate(events) if e.marker == marker]


def next_major_index(events: List[Event], start: int) -> int:
    for i in range(start + 1, len(events)):
        if events[i].marker in MAJOR_MARKERS:
            return i
    return len(events)


def blob_bytes(event: Optional[Event], length: int = 40) -> bytes:
    if event is None:
        return b""

    out = bytearray()
    for blob in event.db_blobs:
        out.extend(blob.data)
        if len(out) >= length:
            break

    return bytes(out[:length])


def blob_addr(event: Optional[Event]) -> Optional[int]:
    if event is None or not event.db_blobs:
        return None
    return event.db_blobs[0].addr


class Reporter:
    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose
        self.failures: List[str] = []
        self.checks: List[Dict[str, object]] = []

    def section(self, title: str) -> None:
        print()
        print("=" * 78)
        print(title)
        print("=" * 78)

    def info(self, msg: str) -> None:
        print(f"[INFO] {msg}")

    def ok(self, name: str, msg: str, **fields: object) -> None:
        print(f"[PASS] {name}: {msg}")
        self.checks.append({"check": name, "pass": True, **fields})

    def fail(self, name: str, msg: str, **fields: object) -> None:
        print(f"[FAIL] {name}: {msg}")
        self.failures.append(name)
        self.checks.append({"check": name, "pass": False, "reason": msg, **fields})

    def warn(self, name: str, msg: str, **fields: object) -> None:
        print(f"[WARN] {name}: {msg}")
        self.checks.append({"check": name, "pass": None, "reason": msg, **fields})

    def detail(self, msg: str) -> None:
        if self.verbose:
            print(f"       {msg}")


def marker_census(events: List[Event], rep: Reporter) -> None:
    rep.section("1. Marker census")

    interesting = [
        "V26_SELFTEST_STATIC_COPY_68011CA3",
        "V26_SELFTEST_AFTER_D640_68011CAA",
        "V26_D640_ENTRY_6800D640",
        "V26_SOURCE_TO_STATE20_SLOT_COPY_6800D677",
        "V26_AFTER_SOURCE_COPY_OR_NULL_6800D679",
        "V26_BEFORE_FIPS_CALL_6800D6F6",
        "V26_FIPS_ENTRY_68027101",
        "V26_FIPS_UPDATE_A_RETURN_680271D5",
        "V26_FIPS_UPDATE_B_RETURN_68027297",
        "V26_AFTER_FIPS_CALL_6800D6FB",
        "V26_BEFORE_OUT_COPY_6800D70E",
        "V26_AFTER_OUT_COPY_6800D713",
        "V26_D640_RETURN_6800D743",
    ]

    counts = {m: 0 for m in interesting}
    for e in events:
        if e.marker in counts:
            counts[e.marker] += 1

    for m in interesting:
        print(f"{m:<45} {counts[m]}")

    rep.info(f"total_events={len(events)}")


def validate_selftest(events: List[Event], rep: Reporter) -> None:
    rep.section("2. Provider self-test: static seed -> local source -> expected state")

    seed_e = first_event(events, "V26_SELFTEST_STATIC_SEED_6802F8B8")
    expected_e = first_event(events, "V26_SELFTEST_EXPECTED_AFTER_6802F8CC")
    stack_after_e = first_event(events, "V26_SELFTEST_STACK_SOURCE_EBP_M28_AFTER")
    state_slot_e = first_event(events, "V26_STATE20_SLOT_68031958")

    seed20 = blob_bytes(seed_e, 20)
    expected20 = blob_bytes(expected_e, 20)
    stack20 = blob_bytes(stack_after_e, 20)
    slot20 = blob_bytes(state_slot_e, 20)

    rep.detail(f"static seed marker line     = {seed_e.line if seed_e else 'missing'}")
    rep.detail(f"expected marker line        = {expected_e.line if expected_e else 'missing'}")
    rep.detail(f"stack source after line     = {stack_after_e.line if stack_after_e else 'missing'}")
    rep.detail(f"state20 slot marker line    = {state_slot_e.line if state_slot_e else 'missing'}")
    rep.detail(f"static seed20               = {hexbytes(seed20, 20)}")
    rep.detail(f"expected after20            = {hexbytes(expected20, 20)}")
    rep.detail(f"stack source after20        = {hexbytes(stack20, 20)}")
    rep.detail(f"state20 slot sample20       = {hexbytes(slot20, 20)}")

    if not stack_after_e or not expected_e:
        rep.fail(
            "selftest_stack_source_equals_6802F8CC",
            "missing V26_SELFTEST_STACK_SOURCE_EBP_M28_AFTER or V26_SELFTEST_EXPECTED_AFTER_6802F8CC",
        )
        return

    if len(stack20) != 20 or len(expected20) != 20:
        rep.fail(
            "selftest_stack_source_equals_6802F8CC",
            f"not enough bytes: stack={len(stack20)} expected={len(expected20)}",
            line=stack_after_e.line,
        )
        return

    if stack20 == expected20:
        rep.ok(
            "selftest_stack_source_equals_6802F8CC",
            "local self-test source after 6800d640 equals expected provider vector at 6802F8CC",
            line=stack_after_e.line,
            stack_source20=stack20.hex(),
            expected20=expected20.hex(),
        )
    else:
        rep.fail(
            "selftest_stack_source_equals_6802F8CC",
            "local self-test source differs from expected provider vector",
            line=stack_after_e.line,
            stack_source20=stack20.hex(),
            expected20=expected20.hex(),
        )


def classify_d640_calls(events: List[Event], rep: Reporter) -> None:
    rep.section("3. 6800d640 calls: source pointer / requested output length / caller class")

    idxs = event_indices(events, "V26_D640_ENTRY_6800D640")

    if not idxs:
        rep.fail("d640_entry_seen", "no V26_D640_ENTRY_6800D640 marker found")
        return

    rep.ok("d640_entry_seen", f"found {len(idxs)} calls to 6800d640", count=len(idxs))

    for n, idx in enumerate(idxs, start=1):
        e = events[idx]
        stop = next_major_index(events, idx)

        args_e = first_event(events, "V26_D640_ARGS_RAW", idx + 1, stop)
        state_e = first_event(events, "V26_STATE20_SLOT_68031958_AT_D640_ENTRY", idx + 1, stop)

        vals = [hexv for _, hexv in (args_e.evals if args_e else [])]
        arg_names = ["arg1", "arg2", "source_arg3", "arg4", "out_dest", "out_len", "writeback_flag"]

        print()
        print(f"Call #{n} @ line {e.line}")

        if vals:
            for name, val in zip(arg_names, vals):
                print(f"  {name:<15} = 0x{val:08x}")

            source = vals[2] if len(vals) > 2 else None
            out_len = vals[5] if len(vals) > 5 else None

            if source == 0:
                print("  classification  = runtime/global-state call; source_arg3 is NULL")
            elif source is not None:
                print("  classification  = source-to-state call; source_arg3 is non-NULL")

            if out_len is not None:
                print(f"  requested len    = 0x{out_len:x} ({out_len} bytes)")
        else:
            print("  args             = not parsed; no V26_D640_ARGS_RAW eval output found")

        state20 = blob_bytes(state_e, 20)
        print(f"  state20 sample   = {hexbytes(state20, 20)}")


def validate_fips(events: List[Event], rep: Reporter) -> None:
    rep.section("4. FIPS boundary and state update markers")

    fips = event_indices(events, "V26_FIPS_ENTRY_68027101")
    update_a = event_indices(events, "V26_FIPS_UPDATE_A_RETURN_680271D5")
    update_b = event_indices(events, "V26_FIPS_UPDATE_B_RETURN_68027297")
    after = event_indices(events, "V26_AFTER_FIPS_CALL_6800D6FB")

    if fips:
        rep.ok("fips_entry_count", f"found {len(fips)} FIPS entries at 68027101", count=len(fips))
    else:
        rep.fail("fips_entry_count", "no FIPS entry marker found")

    if update_a:
        rep.ok("fips_update_A_seen", f"found {len(update_a)} update-A return markers at 680271D5", count=len(update_a))
    else:
        rep.fail("fips_update_A_seen", "no update-A marker found")

    if update_b:
        rep.ok("fips_update_B_seen", f"found {len(update_b)} update-B return markers at 68027297", count=len(update_b))
    else:
        rep.fail("fips_update_B_seen", "no update-B marker found")

    if after:
        rep.ok("after_fips_seen", f"found {len(after)} after-FIPS markers at 6800D6FB", count=len(after))
    else:
        rep.fail("after_fips_seen", "no after-FIPS marker found")

    for n, idx in enumerate(after, start=1):
        stop = next_major_index(events, idx)
        state_e = first_event(events, "V26_STATE20_AFTER_FIPS_SLOT", idx + 1, stop)
        out40_e = first_event(events, "V26_OUT40_LOCAL_AFTER_FIPS_EBP_M40", idx + 1, stop)
        aux_e = first_event(events, "V26_AUX20_LOCAL_AFTER_FIPS_EBP_M18", idx + 1, stop)

        state20 = blob_bytes(state_e, 20)
        out40 = blob_bytes(out40_e, 40)
        aux20 = blob_bytes(aux_e, 20)

        print()
        print(f"After-FIPS #{n} @ line {events[idx].line}")
        print(f"  state20_after = {hexbytes(state20, 20)}")
        print(f"  out40         = {hexbytes(out40, 40)}")
        print(f"  aux20         = {hexbytes(aux20, 20)}")


def validate_out_copies(events: List[Event], rep: Reporter) -> None:
    rep.section("5. Output copy: out40[:len] -> caller buffer")

    idxs = event_indices(events, "V26_AFTER_OUT_COPY_6800D713")

    if not idxs:
        rep.fail("out_copy_prefix_summary", "no V26_AFTER_OUT_COPY_6800D713 marker found")
        return

    total = 0
    passed = 0

    for n, idx in enumerate(idxs, start=1):
        e = events[idx]
        stop = next_major_index(events, idx)

        dest_e = first_event(events, "V26_OUT_DEST_AFTER_COPY", idx + 1, stop)
        out40_e = first_event(events, "V26_OUT40_LOCAL_AFTER_COPY_EBP_M40", idx + 1, stop)
        len_e = first_event(events, "V26_OUT_COPY_LEN_REGISTER_ESI", idx + 1, stop)

        dest = blob_bytes(dest_e, 40)
        out40 = blob_bytes(out40_e, 40)

        copy_len = e.regs.get("esi")

        if (copy_len is None or copy_len <= 0 or copy_len > 40) and len_e and len_e.evals:
            copy_len = len_e.evals[0][1]

        if copy_len is None or copy_len <= 0 or copy_len > 40:
            copy_len = min(len(dest), len(out40), 40)

        total += 1

        dest_addr = blob_addr(dest_e)
        out40_addr = blob_addr(out40_e)

        ok = len(dest) >= copy_len and len(out40) >= copy_len and dest[:copy_len] == out40[:copy_len]

        print()
        print(f"Copy #{n} @ line {e.line}")
        print(f"  effective length = 0x{copy_len:x} ({copy_len} bytes)")
        print(f"  destination      = {f'0x{dest_addr:08x}' if dest_addr is not None else '<missing>'}")
        print(f"  out40 local      = {f'0x{out40_addr:08x}' if out40_addr is not None else '<missing>'}")
        print(f"  dest[:len]       = {hexbytes(dest[:copy_len], copy_len)}")
        print(f"  out40[:len]      = {hexbytes(out40[:copy_len], copy_len)}")

        if ok:
            passed += 1
            rep.ok(
                "out_copy_prefix",
                f"destination prefix equals out40 prefix for {copy_len} bytes",
                line=e.line,
                length=copy_len,
                dest_addr=dest_addr,
                out40_addr=out40_addr,
                dest_prefix=dest[:copy_len].hex(),
                out40_prefix=out40[:copy_len].hex(),
            )
        else:
            if not dest_e:
                reason = "missing V26_OUT_DEST_AFTER_COPY marker"
            elif not out40_e:
                reason = "missing V26_OUT40_LOCAL_AFTER_COPY_EBP_M40 marker"
            elif len(dest) < copy_len:
                reason = f"destination dump too short: have {len(dest)}, need {copy_len}"
            elif len(out40) < copy_len:
                reason = f"out40 dump too short: have {len(out40)}, need {copy_len}"
            else:
                mismatch_at = next(
                    (i for i in range(copy_len) if dest[i] != out40[i]),
                    None,
                )
                reason = f"prefix mismatch at byte {mismatch_at}: dest={dest[mismatch_at]:02x} out40={out40[mismatch_at]:02x}"

            rep.fail(
                "out_copy_prefix",
                reason,
                line=e.line,
                length=copy_len,
                dest_prefix=dest[:copy_len].hex(),
                out40_prefix=out40[:copy_len].hex(),
            )

    if total > 0 and total == passed:
        rep.ok(
            "out_copy_prefix_summary",
            f"all output copies passed ({passed}/{total})",
            pass_count=passed,
            total=total,
        )
    else:
        rep.fail(
            "out_copy_prefix_summary",
            f"only {passed}/{total} output copies passed",
            pass_count=passed,
            total=total,
        )


def write_jsonl(path: str, events: List[Event], checks: List[Dict[str, object]]) -> None:
    out = pathlib.Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps({
                "type": "event",
                "marker": e.marker,
                "line": e.line,
                "regs": {k: f"0x{v:08x}" for k, v in e.regs.items()},
                "db_blobs": [
                    {
                        "line": b.line,
                        "addr": f"0x{b.addr:08x}",
                        "hex": b.data.hex(),
                    }
                    for b in e.db_blobs
                ],
                "evals": [
                    {
                        "dec": dec,
                        "hex": f"0x{hexv:08x}",
                    }
                    for dec, hexv in e.evals
                ],
            }) + "\n")

        for c in checks:
            f.write(json.dumps({"type": "check", **c}) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verbose parser/validator for seed2state V26 rsaenh provider-only logs."
    )
    ap.add_argument("log", help="WinDbg/KD log to parse")
    ap.add_argument("--jsonl", help="Optional JSONL output path")
    ap.add_argument("--quiet", action="store_true", help="Less detail in the human report")
    args = ap.parse_args()

    log_path = pathlib.Path(args.log)
    if not log_path.exists():
        print(f"[FATAL] log not found: {log_path}", file=sys.stderr)
        return 2

    lines = log_path.read_text(errors="replace").splitlines()
    events = collect_events(lines)

    rep = Reporter(verbose=not args.quiet)

    print(f"V26_RSAENH_PROVIDER_VERBOSE")
    print(f"log={log_path}")
    print(f"lines={len(lines)}")
    print(f"events={len(events)}")

    marker_census(events, rep)
    validate_selftest(events, rep)
    classify_d640_calls(events, rep)
    validate_fips(events, rep)
    validate_out_copies(events, rep)

    rep.section("6. Final verdict")

    required = {
        "selftest_stack_source_equals_6802F8CC",
        "fips_entry_count",
        "fips_update_A_seen",
        "fips_update_B_seen",
        "after_fips_seen",
        "out_copy_prefix_summary",
    }

    by_check: Dict[str, bool] = {}
    for c in rep.checks:
        name = str(c["check"])
        if name in required:
            by_check[name] = bool(c.get("pass"))

    missing = sorted(k for k in required if k not in by_check)
    failed = sorted(k for k, ok in by_check.items() if not ok)

    if missing:
        print("[REVIEW] Missing required checks:")
        for k in missing:
            print(f"         - {k}")

    if failed:
        print("[REVIEW] Failed required checks:")
        for k in failed:
            print(f"         - {k}")

    if not missing and not failed:
        print("[PASS] OVERALL: provider-local transition validated for this log")
        print("       Meaning:")
        print("       - self-test provider vector is coherent")
        print("       - FIPS entries were observed")
        print("       - both FIPS state-update return sites were observed")
        print("       - every captured output copy satisfies dest[:len] == out40[:len]")
        overall = True
    else:
        print("[REVIEW] OVERALL: provider-local transition is incomplete or needs inspection")
        overall = False

    if args.jsonl:
        write_jsonl(args.jsonl, events, rep.checks)
        print()
        print(f"[INFO] wrote JSONL: {args.jsonl}")

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
