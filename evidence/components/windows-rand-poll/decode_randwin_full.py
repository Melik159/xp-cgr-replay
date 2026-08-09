#!/usr/bin/env python3
"""
decode_randwin_full.py

Decode, sort, compare, and structurally validate selected Windows RAND_poll
records stored in randwin_full.json files.

The tool supports:

  1. a single randwin_full.json file;
  2. a directory containing one or more randwin_full.json files;
  3. specialized views for modules, processes, threads, heaps, Lanman,
     timing, memory, and opaque blobs.

Important scope note:

This tool does not concatenate RAND_poll inputs and does not claim to replay
OpenSSL state transitions. It validates that selected records are well-formed
Windows structures and that decoded fields are internally consistent with the
trace metadata.

CryptGenRandom records are intentionally treated as opaque provider output
blobs. They are reported by length, SHA-256, and short previews, not decoded as
Win32 structures.

Examples:

    python3 decode_randwin_full.py sample01/randwin_full.json --summary --validate
    python3 decode_randwin_full.py . --recursive --summary --validate
    python3 decode_randwin_full.py sample01/randwin_full.json --modules
    python3 decode_randwin_full.py . --recursive --modules --grep advapi
    python3 decode_randwin_full.py . --recursive --modules-unique
    python3 decode_randwin_full.py . --recursive --modules-unique --sort snapshots --desc
    python3 decode_randwin_full.py . --recursive --modules-presence
    python3 decode_randwin_full.py sample01/randwin_full.json --processes
    python3 decode_randwin_full.py sample01/randwin_full.json --timing
    python3 decode_randwin_full.py sample01/randwin_full.json --lanman
    python3 decode_randwin_full.py sample01/randwin_full.json --memory
    python3 decode_randwin_full.py . --recursive --compare-sources
    python3 decode_randwin_full.py . --recursive --coherence
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class ValidationItem:
    index: int
    source: str
    message: str


@dataclass(frozen=True)
class RandwinRun:
    name: str
    path: Path
    records: list[dict[str, Any]]


Decoder = Callable[[bytes], dict[str, Any]]


# ---------------------------------------------------------------------------
# Basic binary helpers
# ---------------------------------------------------------------------------


def clean_hex(value: str) -> str:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(cleaned) % 2:
        raise ValueError("odd-length hex string")
    return cleaned.upper()


def to_bytes(hexstr: str) -> bytes:
    return bytes.fromhex(clean_hex(hexstr))


def u32le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def i32le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def u64le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def filetime_to_utc(value: int) -> str:
    # FILETIME is a count of 100 ns intervals since 1601-01-01 UTC.
    dt = FILETIME_EPOCH + timedelta(microseconds=value // 10)
    return dt.isoformat().replace("+00:00", "Z")


def ascii_cstr(buf: bytes, off: int, size: int) -> str:
    raw = buf[off:off + size].split(b"\x00", 1)[0]
    return raw.decode("ascii", errors="replace")


def ascii_preview(buf: bytes, limit: int = 96) -> str:
    part = buf[:limit]
    return "".join(chr(x) if 32 <= x <= 126 else "." for x in part)


def hex_preview(buf: bytes, limit: int = 64) -> str:
    part = buf[:limit]
    out = part.hex().upper()
    if len(buf) > limit:
        out += "..."
    return out


def first_hex(buf: bytes, limit: int = 16) -> str:
    return buf[:limit].hex().upper()


def sha256_hex(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


def fmt_addr(value: int) -> str:
    return f"0x{value:08X}"


def match_grep(grep: str | None, *values: object) -> bool:
    if not grep:
        return True
    needle = grep.casefold()
    return any(needle in str(v).casefold() for v in values if v is not None)


# ---------------------------------------------------------------------------
# Input discovery and loading
# ---------------------------------------------------------------------------


def run_name_from_path(path: Path) -> str:
    if path.name == "randwin_full.json":
        return path.parent.name or path.stem
    return path.stem


def discover_json_files(input_path: Path, recursive: bool) -> list[Path]:
    if input_path.is_file():
        return [input_path]

    if not input_path.is_dir():
        raise SystemExit(f"ERROR: input path does not exist: {input_path}")

    if recursive:
        files = sorted(input_path.rglob("randwin_full.json"))
    else:
        direct = input_path / "randwin_full.json"
        files = [direct] if direct.exists() else sorted(input_path.glob("*/randwin_full.json"))

    if not files:
        mode = "recursively" if recursive else "in the directory or one level below it"
        raise SystemExit(f"ERROR: no randwin_full.json found {mode}: {input_path}")

    return files


def load_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, list):
        raise SystemExit(f"ERROR: top-level JSON object must be a list: {path}")
    return data


def load_runs(input_path: Path, recursive: bool) -> list[RandwinRun]:
    runs: list[RandwinRun] = []
    for path in discover_json_files(input_path, recursive):
        runs.append(RandwinRun(run_name_from_path(path), path, load_records(path)))
    return runs


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def raw_record(raw: bytes) -> dict[str, Any]:
    return {
        "raw_len": len(raw),
        "sha256": sha256_hex(raw),
        "first16": first_hex(raw),
        "hex_preview": hex_preview(raw),
        "ascii_preview": ascii_preview(raw),
    }


def blob_record(raw: bytes) -> dict[str, Any]:
    return {
        "raw_len": len(raw),
        "sha256": sha256_hex(raw),
        "first16": first_hex(raw),
        "hex_preview": hex_preview(raw),
    }


def decode_lanman_workstation(raw: bytes) -> dict[str, Any]:
    if len(raw) < 20:
        raise ValueError("LanmanWorkstation record shorter than 20 bytes")

    ft = u64le(raw, 0)

    return {
        "raw_len": len(raw),
        "StatisticsStartTime": f"0x{ft:016X}",
        "StatisticsStartTimeUTC": filetime_to_utc(ft),
        "BytesReceived": u32le(raw, 8),
        "SmbsReceived": u32le(raw, 12),
        "PagingReadBytesRequested": u32le(raw, 16),
        "sha256": sha256_hex(raw),
        "hex_preview": hex_preview(raw),
        "ascii_preview": ascii_preview(raw),
    }


def decode_lanman_server(raw: bytes) -> dict[str, Any]:
    if len(raw) < 4:
        raise ValueError("LanmanServer record shorter than 4 bytes")

    return {
        "raw_len": len(raw),
        "first_u32": u32le(raw, 0),
        "sha256": sha256_hex(raw),
        "first16": first_hex(raw),
        "hex_preview": hex_preview(raw),
        "ascii_preview": ascii_preview(raw),
    }


def decode_heap32list(raw: bytes) -> dict[str, Any]:
    if len(raw) != 16:
        raise ValueError("Heap32List must be 16 bytes")

    return {
        "dwSize": u32le(raw, 0),
        "th32ProcessID": u32le(raw, 4),
        "th32HeapID": fmt_addr(u32le(raw, 8)),
        "dwFlags": u32le(raw, 12),
        "hex": raw.hex().upper(),
    }


def decode_heap32entry(raw: bytes) -> dict[str, Any]:
    if len(raw) != 36:
        raise ValueError("Heap32Entry must be 36 bytes")

    return {
        "dwSize": u32le(raw, 0),
        "hHandle": fmt_addr(u32le(raw, 4)),
        "dwAddress": fmt_addr(u32le(raw, 8)),
        "dwBlockSize": u32le(raw, 12),
        "dwFlags": u32le(raw, 16),
        "dwLockCount": u32le(raw, 20),
        "dwResvd": u32le(raw, 24),
        "th32ProcessID": u32le(raw, 28),
        "th32HeapID": fmt_addr(u32le(raw, 32)),
        "hex": raw.hex().upper(),
    }


def decode_processentry(raw: bytes) -> dict[str, Any]:
    if len(raw) != 296:
        raise ValueError("ProcessEntry must be 296 bytes")

    return {
        "dwSize": u32le(raw, 0),
        "cntUsage": u32le(raw, 4),
        "th32ProcessID": u32le(raw, 8),
        "th32DefaultHeapID": fmt_addr(u32le(raw, 12)),
        "th32ModuleID": u32le(raw, 16),
        "cntThreads": u32le(raw, 20),
        "th32ParentProcessID": u32le(raw, 24),
        "pcPriClassBase": i32le(raw, 28),
        "dwFlags": u32le(raw, 32),
        "szExeFile": ascii_cstr(raw, 36, 260),
        "hex_preview": hex_preview(raw),
        "ascii_preview": ascii_preview(raw),
    }


def decode_threadentry(raw: bytes) -> dict[str, Any]:
    if len(raw) != 28:
        raise ValueError("ThreadEntry must be 28 bytes")

    return {
        "dwSize": u32le(raw, 0),
        "cntUsage": u32le(raw, 4),
        "th32ThreadID": u32le(raw, 8),
        "th32OwnerProcessID": u32le(raw, 12),
        "tpBasePri": i32le(raw, 16),
        "tpDeltaPri": i32le(raw, 20),
        "dwFlags": u32le(raw, 24),
        "hex": raw.hex().upper(),
    }


def decode_moduleentry(raw: bytes) -> dict[str, Any]:
    if len(raw) != 548:
        raise ValueError("ModuleEntry must be 548 bytes")

    module_name = ascii_cstr(raw, 32, 256)
    exe_path = ascii_cstr(raw, 288, 260)

    return {
        "dwSize": u32le(raw, 0),
        "th32ModuleID": u32le(raw, 4),
        "th32ProcessID": u32le(raw, 8),
        "GlblcntUsage": u32le(raw, 12),
        "ProccntUsage": u32le(raw, 16),
        "modBaseAddr": fmt_addr(u32le(raw, 20)),
        "modBaseSize": u32le(raw, 24),
        "hModule": fmt_addr(u32le(raw, 28)),
        "szModule": module_name,
        "szExePath": exe_path,
        "hex_preview": hex_preview(raw),
        "ascii_preview": ascii_preview(raw),
    }


def decode_global_memory_status(raw: bytes) -> dict[str, Any]:
    if len(raw) != 32:
        raise ValueError("GlobalMemoryStatus must be 32 bytes")

    names = [
        "dwLength",
        "dwMemoryLoad",
        "dwTotalPhys",
        "dwAvailPhys",
        "dwTotalPageFile",
        "dwAvailPageFile",
        "dwTotalVirtual",
        "dwAvailVirtual",
    ]

    return {name: u32le(raw, i * 4) for i, name in enumerate(names)}


def decode_query_performance_counter(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8:
        raise ValueError("QueryPerformanceCounter must be 8 bytes")

    return {
        "counter_u64": u64le(raw, 0),
        "hex": raw.hex().upper(),
    }


def decode_current_process_id(raw: bytes) -> dict[str, Any]:
    if len(raw) != 4:
        raise ValueError("GetCurrentProcessId must be 4 bytes")

    return {
        "pid": u32le(raw, 0),
        "hex": raw.hex().upper(),
    }


def decode_u32_record(raw: bytes) -> dict[str, Any]:
    if len(raw) != 4:
        raise ValueError("record must be 4 bytes")

    return {
        "u32": u32le(raw, 0),
        "hex": raw.hex().upper(),
    }


DECODERS: dict[str, Decoder] = {
    "LanmanWorkstation": decode_lanman_workstation,
    "LanmanServer": decode_lanman_server,
    "Heap32List": decode_heap32list,
    "Heap32Entry": decode_heap32entry,
    "ProcessEntry": decode_processentry,
    "ThreadEntry": decode_threadentry,
    "ModuleEntry": decode_moduleentry,
    "GlobalMemoryStatus": decode_global_memory_status,
    "QueryPerformanceCounter": decode_query_performance_counter,
    "GetCurrentProcessId": decode_current_process_id,
    "GetForegroundWindow": decode_u32_record,
    "GetQueueStatus": decode_u32_record,
}

OPAQUE_BLOB_SOURCES = {
    "CryptGenRandom",
}


def decode_record(record: dict[str, Any]) -> dict[str, Any]:
    raw = to_bytes(record.get("hex", ""))
    source = record.get("source", "?")

    if source in OPAQUE_BLOB_SOURCES:
        decoded = blob_record(raw)
    else:
        decoder = DECODERS.get(source)
        decoded = decoder(raw) if decoder else raw_record(raw)

    return {
        "index": record.get("index"),
        "source": source,
        "length": record.get("length"),
        "entropy": record.get("entropy"),
        "file": record.get("file"),
        "decoded": decoded,
    }


def iter_decoded(
    run: RandwinRun,
    source: str | None = None,
) -> Iterable[tuple[dict[str, Any], bytes, dict[str, Any]]]:
    for record in run.records:
        if source and record.get("source") != source:
            continue
        raw = to_bytes(record.get("hex", ""))
        yield record, raw, decode_record(record)["decoded"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_record_shape(records: list[dict[str, Any]]) -> list[ValidationItem]:
    errors: list[ValidationItem] = []

    for pos, r in enumerate(records):
        source = r.get("source", "?")
        idx = r.get("index", -1)

        if idx != pos:
            errors.append(
                ValidationItem(pos, source, f"index field {idx} != array position {pos}")
            )

        for key in ("index", "source", "length", "hex"):
            if key not in r:
                errors.append(ValidationItem(pos, source, f"missing key: {key}"))

        try:
            raw = to_bytes(r.get("hex", ""))
        except Exception as exc:
            errors.append(ValidationItem(pos, source, f"invalid hex: {exc}"))
            continue

        if len(raw) != r.get("length"):
            errors.append(
                ValidationItem(
                    pos,
                    source,
                    f"length mismatch: metadata={r.get('length')} actual={len(raw)}",
                )
            )

    return errors


def validate_semantics(
    records: list[dict[str, Any]],
) -> tuple[list[ValidationItem], list[ValidationItem]]:
    errors: list[ValidationItem] = []
    warnings: list[ValidationItem] = []

    process_pids: set[int] = set()
    current_pids: set[int] = set()
    qpc_values: list[tuple[int, int]] = []

    for r in records:
        idx = int(r.get("index", -1))
        source = r.get("source", "?")

        try:
            raw = to_bytes(r.get("hex", ""))
            decoder = DECODERS.get(source)
            decoded = decoder(raw) if decoder else None
        except Exception as exc:
            errors.append(ValidationItem(idx, source, str(exc)))
            continue

        if source == "CryptGenRandom":
            # Opaque by design: validate only length/hash metadata shape elsewhere.
            continue

        if source == "GetCursorInfo":
            # Some traces contain a zero-length placeholder for this source.
            continue

        if source == "LanmanWorkstation":
            if len(raw) != 216:
                warnings.append(
                    ValidationItem(
                        idx,
                        source,
                        f"observed length is {len(raw)}, expected common length 216",
                    )
                )

        elif source == "LanmanServer":
            if len(raw) != 68:
                warnings.append(
                    ValidationItem(
                        idx,
                        source,
                        f"observed length is {len(raw)}, expected common length 68",
                    )
                )

        elif source == "Heap32List":
            if decoded is not None and decoded["dwSize"] != 16:
                errors.append(ValidationItem(idx, source, f"dwSize={decoded['dwSize']} != 16"))

        elif source == "Heap32Entry":
            if decoded is not None and decoded["dwSize"] != 36:
                errors.append(ValidationItem(idx, source, f"dwSize={decoded['dwSize']} != 36"))

        elif source == "ProcessEntry":
            if decoded is not None:
                if decoded["dwSize"] != 296:
                    errors.append(ValidationItem(idx, source, f"dwSize={decoded['dwSize']} != 296"))
                if not decoded["szExeFile"]:
                    errors.append(ValidationItem(idx, source, "empty szExeFile"))
                process_pids.add(decoded["th32ProcessID"])

        elif source == "ThreadEntry":
            if decoded is not None and decoded["dwSize"] != 28:
                errors.append(ValidationItem(idx, source, f"dwSize={decoded['dwSize']} != 28"))

        elif source == "ModuleEntry":
            if decoded is not None:
                if decoded["dwSize"] != 548:
                    errors.append(ValidationItem(idx, source, f"dwSize={decoded['dwSize']} != 548"))
                if not decoded["szModule"]:
                    errors.append(ValidationItem(idx, source, "empty szModule"))

        elif source == "GlobalMemoryStatus":
            if decoded is not None and decoded["dwLength"] != 32:
                errors.append(ValidationItem(idx, source, f"dwLength={decoded['dwLength']} != 32"))

        elif source == "QueryPerformanceCounter":
            if decoded is not None:
                qpc_values.append((idx, decoded["counter_u64"]))

        elif source == "GetCurrentProcessId":
            if decoded is not None:
                current_pids.add(decoded["pid"])

    for (_idx_a, a), (idx_b, b) in zip(qpc_values, qpc_values[1:]):
        if b < a:
            errors.append(
                ValidationItem(
                    idx_b,
                    "QueryPerformanceCounter",
                    f"counter decreased: previous={a} current={b}",
                )
            )

    # Non-fatal: Toolhelp snapshots may be partial or taken at slightly
    # different times.
    for pid in sorted(current_pids):
        if process_pids and pid not in process_pids:
            warnings.append(
                ValidationItem(
                    -1,
                    "GetCurrentProcessId",
                    f"pid {pid} not present in ProcessEntry snapshot",
                )
            )

    return errors, warnings


# ---------------------------------------------------------------------------
# Summary views
# ---------------------------------------------------------------------------


def print_run_summary(run: RandwinRun) -> None:
    records = run.records
    print(f"randwin_full structural summary: run={run.name}")
    print("-" * 72)
    print(f"file        : {run.path}")
    print(f"records     : {len(records)}")
    print(f"total bytes : {sum(int(r.get('length', 0)) for r in records)}")
    print(f"sources     : {len(set(r.get('source') for r in records))}")
    print()

    counts = Counter(r.get("source", "?") for r in records)

    for source, count in counts.most_common():
        total = sum(int(r.get("length", 0)) for r in records if r.get("source") == source)
        print(f"{source:24} count={count:<5} bytes={total}")


def print_aggregate_summary(runs: list[RandwinRun]) -> None:
    if len(runs) <= 1:
        return

    print()
    print("aggregate source summary")
    print("-" * 72)
    print(f"runs        : {len(runs)}")
    print(f"records     : {sum(len(run.records) for run in runs)}")
    print(f"total bytes : {sum(int(r.get('length', 0)) for run in runs for r in run.records)}")
    print()
    print(f"{'source':24} {'runs':>7} {'count_range':>15} {'bytes_range':>17}")

    all_sources = sorted({r.get("source", "?") for run in runs for r in run.records})
    for source in all_sources:
        counts: list[int] = []
        byte_counts: list[int] = []
        present = 0
        for run in runs:
            selected = [r for r in run.records if r.get("source") == source]
            if selected:
                present += 1
            counts.append(len(selected))
            byte_counts.append(sum(int(r.get("length", 0)) for r in selected))
        count_range = f"{min(counts)}..{max(counts)}"
        bytes_range = f"{min(byte_counts)}..{max(byte_counts)}"
        print(f"{source:24} {present:>3}/{len(runs):<3} {count_range:>15} {bytes_range:>17}")


def print_summary(runs: list[RandwinRun]) -> None:
    for i, run in enumerate(runs):
        if i:
            print()
        print_run_summary(run)
    print_aggregate_summary(runs)


# ---------------------------------------------------------------------------
# Specialized views
# ---------------------------------------------------------------------------


def process_maps(run: RandwinRun) -> dict[int, str]:
    out: dict[int, str] = {}
    for _record, _raw, decoded in iter_decoded(run, "ProcessEntry"):
        out[int(decoded["th32ProcessID"])] = str(decoded["szExeFile"])
    return out



def sort_text_key(value: object) -> str:
    return str(value).casefold()


def sort_int_from_hex_or_int(value: object) -> int:
    if isinstance(value, int):
        return value
    text_value = str(value)
    try:
        return int(text_value, 0)
    except ValueError:
        return 0


def module_rows(runs: list[RandwinRun], grep: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        for record, _raw, decoded in iter_decoded(run, "ModuleEntry"):
            module = decoded["szModule"]
            path = decoded["szExePath"]
            base = decoded["modBaseAddr"]
            if not match_grep(grep, module, path, base, decoded["th32ProcessID"]):
                continue
            rows.append(
                {
                    "run": run.name,
                    "index": int(record.get("index", -1)),
                    "module": module,
                    "module_key": module.casefold(),
                    "base": base,
                    "base_int": sort_int_from_hex_or_int(base),
                    "size": int(decoded["modBaseSize"]),
                    "path": path,
                    "pid": int(decoded["th32ProcessID"]),
                    "hmodule": decoded["hModule"],
                }
            )
    return rows


def sorted_module_rows(rows: list[dict[str, Any]], sort_key: str | None, desc: bool) -> list[dict[str, Any]]:
    key = sort_key or "run,index"
    keys = [part.strip() for part in key.split(",") if part.strip()]
    allowed = {"run", "index", "module", "base", "size", "path", "pid", "snapshots", "first_index", "last_index"}
    invalid = [part for part in keys if part not in allowed]
    if invalid:
        raise SystemExit(
            "ERROR: unsupported --sort for module view: "
            + ",".join(invalid)
            + f"; allowed: {','.join(sorted(allowed))}"
        )

    def row_key(row: dict[str, Any]) -> tuple[Any, ...]:
        out: list[Any] = []
        for part in keys:
            if part == "base":
                out.append(row["base_int"])
            elif part in {"index", "size", "pid", "snapshots", "first_index", "last_index"}:
                out.append(int(row.get(part, 0)))
            else:
                out.append(sort_text_key(row[part]))
        return tuple(out)

    return sorted(rows, key=row_key, reverse=desc)


def unique_module_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str, int], dict[str, Any]] = {}
    for row in rows:
        key = (row["run"], row["module_key"], row["base"], row["path"], row["pid"])
        if key not in groups:
            groups[key] = dict(row)
            groups[key]["indices"] = []
            groups[key]["snapshots"] = 0
        groups[key]["indices"].append(row["index"])
        groups[key]["snapshots"] += 1

    out = list(groups.values())
    for row in out:
        row["first_index"] = min(row["indices"])
        row["last_index"] = max(row["indices"])
    return out


def print_modules(
    runs: list[RandwinRun],
    grep: str | None,
    limit: int | None,
    *,
    unique: bool,
    presence_only: bool,
    sort_key: str | None,
    desc: bool,
    aggregate: bool,
) -> None:
    rows = module_rows(runs, grep)

    if presence_only:
        print_module_presence(runs, rows, grep, sort_key, desc)
        return

    print("ModuleEntry rows" if not unique else "Unique module rows")
    print("-" * 72)

    if not rows:
        suffix = f" for grep={grep!r}" if grep else ""
        print(f"(no ModuleEntry records matched{suffix})")
        return

    if unique:
        unique_rows = unique_module_rows(rows)
        unique_rows = sorted_module_rows(unique_rows, sort_key or "run,module,base,path", desc)
        selected = unique_rows[:limit] if limit is not None else unique_rows
        for row in selected:
            print(
                f"run={row['run']} module={row['module']:<18} base={row['base']} "
                f"size={row['size']:<8} pid={row['pid']:<6} "
                f"snapshots={row['snapshots']:<3} "
                f"first_index={row['first_index']:<4} last_index={row['last_index']:<4} "
                f"path={row['path']}"
            )
    else:
        sorted_rows = sorted_module_rows(rows, sort_key or "run,index", desc)
        selected = sorted_rows[:limit] if limit is not None else sorted_rows
        for row in selected:
            print(
                f"run={row['run']} index={row['index']} "
                f"module={row['module']:<18} base={row['base']} "
                f"size={row['size']:<8} pid={row['pid']:<6} path={row['path']}"
            )

    if len(runs) > 1 and aggregate:
        print()
        print_module_presence(runs, rows, grep, sort_key=None, desc=False, header="Module presence matrix")


def print_module_presence(
    runs: list[RandwinRun],
    rows: list[dict[str, Any]] | None,
    grep: str | None,
    sort_key: str | None,
    desc: bool,
    header: str = "Module presence matrix",
) -> None:
    if rows is None:
        rows = module_rows(runs, grep)

    print(header)
    print("-" * 72)

    if not rows:
        suffix = f" for grep={grep!r}" if grep else ""
        print(f"(no ModuleEntry records matched{suffix})")
        return

    aggregate: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "display": "",
            "runs": set(),
            "bases": set(),
            "paths": set(),
            "entries": 0,
        }
    )
    for row in rows:
        key = row["module_key"]
        aggregate[key]["display"] = row["module"]
        aggregate[key]["runs"].add(row["run"])
        aggregate[key]["bases"].add(row["base"])
        aggregate[key]["paths"].add(row["path"])
        aggregate[key]["entries"] += 1

    presence_rows: list[dict[str, Any]] = []
    for key, item in aggregate.items():
        presence_rows.append(
            {
                "module": item["display"],
                "module_key": key,
                "runs_present": len(item["runs"]),
                "run_total": len(runs),
                "bases": sorted(item["bases"]),
                "paths": sorted(item["paths"]),
                "entries": int(item["entries"]),
            }
        )

    allowed = {"module", "runs", "bases", "paths", "entries"}
    key = sort_key or "module"
    if key not in allowed:
        raise SystemExit(
            f"ERROR: unsupported --sort for module presence: {key}; allowed: {','.join(sorted(allowed))}"
        )

    def presence_key(row: dict[str, Any]) -> Any:
        if key == "runs":
            return row["runs_present"]
        if key == "entries":
            return row["entries"]
        if key == "bases":
            return ",".join(row["bases"])
        if key == "paths":
            return ",".join(row["paths"])
        return sort_text_key(row["module"])

    presence_rows = sorted(presence_rows, key=presence_key, reverse=desc)

    print(f"{'module':24} {'runs_present':>13} {'entries':>8}  bases_observed  paths_observed")
    for row in presence_rows:
        bases = ",".join(row["bases"])
        paths = " | ".join(row["paths"])
        print(
            f"{row['module']:24} {row['runs_present']:>3}/{row['run_total']:<9} "
            f"{row['entries']:>8}  {bases}  {paths}"
        )


def print_processes(runs: list[RandwinRun], grep: str | None, limit: int | None) -> None:
    print("Processes")
    print("-" * 72)
    printed = 0
    aggregate: dict[str, set[str]] = defaultdict(set)

    for run in runs:
        for record, _raw, decoded in iter_decoded(run, "ProcessEntry"):
            exe = decoded["szExeFile"]
            pid = decoded["th32ProcessID"]
            ppid = decoded["th32ParentProcessID"]
            if not match_grep(grep, exe, pid, ppid):
                continue

            print(
                f"run={run.name} index={record.get('index')} "
                f"pid={pid:<6} ppid={ppid:<6} threads={decoded['cntThreads']:<3} "
                f"pri={decoded['pcPriClassBase']:<3} exe={exe}"
            )
            aggregate[exe.casefold()].add(run.name)
            printed += 1
            if limit is not None and printed >= limit:
                break
        if limit is not None and printed >= limit:
            break

    if len(runs) > 1 and aggregate:
        print()
        print("Process executable presence across runs")
        print("-" * 72)
        print(f"{'exe':32} {'runs_present':>13}")
        for exe_key in sorted(aggregate):
            display = exe_key
            print(f"{display:32} {len(aggregate[exe_key]):>3}/{len(runs):<9}")



def print_threads(runs: list[RandwinRun], grep: str | None, limit: int | None) -> None:
    print("Threads")
    print("-" * 72)
    printed = 0

    for run in runs:
        pids = process_maps(run)
        owner_counts: Counter[int] = Counter()
        rows: list[tuple[dict[str, Any], dict[str, Any]]] = []

        for record, _raw, decoded in iter_decoded(run, "ThreadEntry"):
            owner = int(decoded["th32OwnerProcessID"])
            owner_counts[owner] += 1
            rows.append((record, decoded))

        print(f"run={run.name}")
        print("  Thread owners")
        for owner, count in owner_counts.most_common():
            exe = pids.get(owner, "?")
            if match_grep(grep, owner, exe):
                print(f"  owner_pid={owner:<6} count={count:<4} exe={exe}")

        print("  Thread entries")
        for record, decoded in rows:
            owner = int(decoded["th32OwnerProcessID"])
            exe = pids.get(owner, "?")
            if not match_grep(grep, decoded["th32ThreadID"], owner, exe):
                continue
            print(
                f"  index={record.get('index')} tid={decoded['th32ThreadID']:<6} "
                f"owner_pid={owner:<6} owner_exe={exe} base_pri={decoded['tpBasePri']}"
            )
            printed += 1
            if limit is not None and printed >= limit:
                return
        print()



def print_heaps(runs: list[RandwinRun], grep: str | None, limit: int | None) -> None:
    print("Heaps")
    print("-" * 72)
    printed = 0

    for run in runs:
        pids = process_maps(run)
        for record, _raw, decoded in iter_decoded(run, "Heap32List"):
            pid = decoded["th32ProcessID"]
            exe = pids.get(pid, "?")
            if not match_grep(grep, pid, exe, decoded["th32HeapID"]):
                continue
            print(
                f"run={run.name} index={record.get('index')} source=Heap32List "
                f"pid={pid:<6} exe={exe} heap={decoded['th32HeapID']} flags={decoded['dwFlags']}"
            )
            printed += 1
            if limit is not None and printed >= limit:
                return

        for record, _raw, decoded in iter_decoded(run, "Heap32Entry"):
            pid = decoded["th32ProcessID"]
            exe = pids.get(pid, "?")
            if not match_grep(grep, pid, exe, decoded["th32HeapID"], decoded["dwAddress"]):
                continue
            print(
                f"run={run.name} index={record.get('index')} source=Heap32Entry "
                f"pid={pid:<6} exe={exe} heap={decoded['th32HeapID']} "
                f"addr={decoded['dwAddress']} size={decoded['dwBlockSize']} flags={decoded['dwFlags']}"
            )
            printed += 1
            if limit is not None and printed >= limit:
                return



def print_lanman(runs: list[RandwinRun], grep: str | None, limit: int | None) -> None:
    print("Lanman")
    print("-" * 72)
    printed = 0

    for run in runs:
        for source in ("LanmanWorkstation", "LanmanServer"):
            for record, _raw, decoded in iter_decoded(run, source):
                if source == "LanmanWorkstation":
                    searchable = (
                        source,
                        decoded["StatisticsStartTimeUTC"],
                        decoded["PagingReadBytesRequested"],
                    )
                    if not match_grep(grep, *searchable):
                        continue
                    print(
                        f"run={run.name} index={record.get('index')} source={source} "
                        f"len={decoded['raw_len']} time={decoded['StatisticsStartTimeUTC']} "
                        f"BytesReceived={decoded['BytesReceived']} "
                        f"SmbsReceived={decoded['SmbsReceived']} "
                        f"PagingReadBytesRequested={decoded['PagingReadBytesRequested']}"
                    )
                else:
                    if not match_grep(grep, source, decoded["first_u32"], decoded["sha256"]):
                        continue
                    print(
                        f"run={run.name} index={record.get('index')} source={source} "
                        f"len={decoded['raw_len']} first_u32={decoded['first_u32']} "
                        f"sha256={decoded['sha256']} first16={decoded['first16']}"
                    )
                printed += 1
                if limit is not None and printed >= limit:
                    return



def print_memory(runs: list[RandwinRun], grep: str | None, limit: int | None) -> None:
    print("GlobalMemoryStatus")
    print("-" * 72)
    printed = 0

    for run in runs:
        for record, _raw, decoded in iter_decoded(run, "GlobalMemoryStatus"):
            if not match_grep(grep, decoded["dwMemoryLoad"], decoded["dwAvailPhys"], decoded["dwAvailVirtual"]):
                continue
            print(
                f"run={run.name} index={record.get('index')} "
                f"load={decoded['dwMemoryLoad']}% "
                f"total_phys={decoded['dwTotalPhys']} avail_phys={decoded['dwAvailPhys']} "
                f"total_pagefile={decoded['dwTotalPageFile']} avail_pagefile={decoded['dwAvailPageFile']} "
                f"total_virtual={decoded['dwTotalVirtual']} avail_virtual={decoded['dwAvailVirtual']}"
            )
            printed += 1
            if limit is not None and printed >= limit:
                return



def print_timing(runs: list[RandwinRun], grep: str | None, limit: int | None) -> None:
    print("Timing / UI counters")
    print("-" * 72)
    printed = 0

    for run in runs:
        previous_qpc: int | None = None
        for record in run.records:
            source = record.get("source")
            if source not in {"QueryPerformanceCounter", "GetForegroundWindow", "GetQueueStatus", "GetCurrentProcessId"}:
                continue
            decoded = decode_record(record)["decoded"]
            if not match_grep(grep, source, decoded):
                continue

            if source == "QueryPerformanceCounter":
                value = int(decoded["counter_u64"])
                delta = "n/a" if previous_qpc is None else str(value - previous_qpc)
                previous_qpc = value
                print(
                    f"run={run.name} index={record.get('index')} source={source} "
                    f"counter={value} delta={delta}"
                )
            elif source == "GetCurrentProcessId":
                print(
                    f"run={run.name} index={record.get('index')} source={source} "
                    f"pid={decoded['pid']}"
                )
            else:
                print(
                    f"run={run.name} index={record.get('index')} source={source} "
                    f"u32={decoded['u32']} hex={decoded['hex']}"
                )

            printed += 1
            if limit is not None and printed >= limit:
                return



def print_blobs(runs: list[RandwinRun], source: str | None, grep: str | None, limit: int | None) -> None:
    print("Opaque blobs")
    print("-" * 72)
    printed = 0

    for run in runs:
        for record in run.records:
            src = str(record.get("source", "?"))
            if source and src != source:
                continue

            raw = to_bytes(record.get("hex", ""))

            if not source:
                is_known_opaque = src in OPAQUE_BLOB_SOURCES
                is_unknown_nonempty = src not in DECODERS and len(raw) > 0
                if not (is_known_opaque or is_unknown_nonempty):
                    continue

            digest = sha256_hex(raw)
            preview = first_hex(raw)
            if not match_grep(grep, src, digest, preview):
                continue

            print(
                f"run={run.name} index={record.get('index')} source={src} "
                f"length={len(raw)} sha256={digest} first16={preview}"
            )
            printed += 1
            if limit is not None and printed >= limit:
                return

    if printed == 0:
        suffix = f" for grep={grep!r}" if grep else ""
        source_suffix = f" source={source!r}" if source else ""
        print(f"(no opaque blob records matched{source_suffix}{suffix})")



def print_compare_sources(runs: list[RandwinRun]) -> None:
    print("Source comparison across runs")
    print("-" * 72)
    print(f"runs: {len(runs)}")
    print()
    print(f"{'source':24} {'runs_present':>13} {'count_range':>15} {'bytes_range':>17}  missing")

    all_sources = sorted({r.get("source", "?") for run in runs for r in run.records})
    for source in all_sources:
        counts: list[int] = []
        bytes_: list[int] = []
        present_runs: set[str] = set()
        missing_runs: list[str] = []

        for run in runs:
            selected = [r for r in run.records if r.get("source") == source]
            counts.append(len(selected))
            bytes_.append(sum(int(r.get("length", 0)) for r in selected))
            if selected:
                present_runs.add(run.name)
            else:
                missing_runs.append(run.name)

        count_range = f"{min(counts)}..{max(counts)}"
        bytes_range = f"{min(bytes_)}..{max(bytes_)}"
        missing = ",".join(missing_runs) if missing_runs else "-"
        print(
            f"{source:24} {len(present_runs):>3}/{len(runs):<9} "
            f"{count_range:>15} {bytes_range:>17}  {missing}"
        )



def print_decoded(runs: list[RandwinRun], source: str | None, limit: int | None) -> None:
    printed = 0

    for run in runs:
        for record in run.records:
            if source and record.get("source") != source:
                continue

            payload = decode_record(record)
            payload["run"] = run.name
            payload["input_path"] = str(run.path)
            print(json.dumps(payload, indent=2, sort_keys=True))
            printed += 1

            if limit is not None and printed >= limit:
                return



def source_stats_by_run(run: RandwinRun) -> dict[str, dict[str, Any]]:
    stats: dict[str, dict[str, Any]] = {}
    for record in run.records:
        source = str(record.get("source", "?"))
        raw = to_bytes(record.get("hex", ""))
        item = stats.setdefault(source, {"count": 0, "bytes": 0, "lengths": Counter()})
        item["count"] += 1
        item["bytes"] += len(raw)
        item["lengths"][len(raw)] += 1
    return stats


def format_length_counts(counter: Counter[int]) -> str:
    return ",".join(f"{length}x{count}" for length, count in sorted(counter.items()))


def print_coherence(runs: list[RandwinRun], grep: str | None) -> None:
    print("Coherence checks")
    print("-" * 72)
    print(f"runs: {len(runs)}")
    for run in runs:
        print(f"run={run.name} file={run.path} records={len(run.records)}")

    print()
    print("Source matrix")
    print("-" * 72)
    all_sources = sorted({str(r.get("source", "?")) for run in runs for r in run.records})
    print(f"{'source':24} {'run':16} {'count':>7} {'bytes':>9} lengths")
    per_run_stats = {run.name: source_stats_by_run(run) for run in runs}
    for source in all_sources:
        if not match_grep(grep, source):
            continue
        for run in runs:
            stats = per_run_stats[run.name].get(source)
            if stats is None:
                print(f"{source:24} {run.name:16} {0:>7} {0:>9} -")
            else:
                print(
                    f"{source:24} {run.name:16} {stats['count']:>7} "
                    f"{stats['bytes']:>9} {format_length_counts(stats['lengths'])}"
                )

    print()
    print_module_presence(runs, module_rows(runs, grep), grep, sort_key="module", desc=False, header="Module matrix")

    print()
    print("CryptGenRandom blob matrix")
    print("-" * 72)
    printed = 0
    for run in runs:
        for record in run.records:
            if record.get("source") != "CryptGenRandom":
                continue
            raw = to_bytes(record.get("hex", ""))
            digest = sha256_hex(raw)
            preview = first_hex(raw)
            if not match_grep(grep, "CryptGenRandom", digest, preview, len(raw)):
                continue
            print(
                f"run={run.name} index={record.get('index')} length={len(raw)} "
                f"sha256={digest} first16={preview}"
            )
            printed += 1
    if printed == 0:
        print("(no CryptGenRandom records matched)")

    print()
    print("Validation status by run")
    print("-" * 72)
    for run in runs:
        shape_errors = validate_record_shape(run.records)
        semantic_errors, warnings = validate_semantics(run.records)
        errors = shape_errors + semantic_errors
        print(
            f"run={run.name} status={'FAIL' if errors else 'PASS'} "
            f"errors={len(errors)} warnings={len(warnings)}"
        )


# ---------------------------------------------------------------------------
# Validation reporting
# ---------------------------------------------------------------------------


def run_validation(runs: list[RandwinRun], json_mode: bool) -> int:
    all_payloads: list[dict[str, Any]] = []
    any_errors = False

    for run in runs:
        shape_errors = validate_record_shape(run.records)
        semantic_errors, warnings = validate_semantics(run.records)
        errors = shape_errors + semantic_errors
        any_errors = any_errors or bool(errors)

        if json_mode:
            all_payloads.append(
                {
                    "run": run.name,
                    "path": str(run.path),
                    "status": "FAIL" if errors else "PASS",
                    "errors": [asdict(e) for e in errors],
                    "warnings": [asdict(w) for w in warnings],
                }
            )
            continue

        print()
        print(f"Validation: run={run.name}")
        print("-" * 72)

        if errors:
            print("VALIDATION: FAIL")
            for e in errors:
                loc = f"index={e.index}" if e.index >= 0 else "global"
                print(f" - ERROR {loc} source={e.source}: {e.message}")
        else:
            print("VALIDATION: PASS" if not warnings else "VALIDATION: PASS (with warnings)")

        if warnings:
            print()
            print("Warnings")
            print("-" * 72)
            for w in warnings:
                loc = f"index={w.index}" if w.index >= 0 else "global"
                print(f" - WARNING {loc} source={w.source}: {w.message}")

    if json_mode:
        payload: dict[str, Any]
        if len(all_payloads) == 1:
            payload = all_payloads[0]
        else:
            payload = {
                "status": "FAIL" if any_errors else "PASS",
                "runs": all_payloads,
            }
        print(json.dumps(payload, indent=2, sort_keys=True))

    return 1 if any_errors else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


HELP_EPILOG = """
Input discovery:
  FILE                         Decode one JSON file.
  DIRECTORY                    Without --recursive: use DIRECTORY/randwin_full.json
                               or immediate */randwin_full.json children.
  DIRECTORY --recursive        Recursively find randwin_full.json files.

Common examples:
  python3 decode_randwin_full.py sample01/randwin_full.json --summary --validate
  python3 decode_randwin_full.py . --recursive --summary --validate
  python3 decode_randwin_full.py . --recursive --compare-sources

Module views:
  python3 decode_randwin_full.py . --recursive --modules
  python3 decode_randwin_full.py . --recursive --modules --grep advapi
  python3 decode_randwin_full.py . --recursive --modules-unique
  python3 decode_randwin_full.py . --recursive --modules-presence
  python3 decode_randwin_full.py . --recursive --modules-unique --sort module,base
  python3 decode_randwin_full.py . --recursive --modules-unique --sort snapshots --desc
  python3 decode_randwin_full.py . --recursive --modules-unique --aggregate

Other specialized views:
  python3 decode_randwin_full.py sample01/randwin_full.json --processes
  python3 decode_randwin_full.py sample01/randwin_full.json --threads
  python3 decode_randwin_full.py sample01/randwin_full.json --heaps
  python3 decode_randwin_full.py sample01/randwin_full.json --lanman
  python3 decode_randwin_full.py sample01/randwin_full.json --memory
  python3 decode_randwin_full.py sample01/randwin_full.json --timing
  python3 decode_randwin_full.py sample01/randwin_full.json --blobs

Filtering and sorting:
  --grep TEXT                  Case-insensitive text filter for specialized views.
  --limit N                    Limit printed rows in detailed views.
  --sort KEY[,KEY...]          Sort key for views that support sorting.
  --desc                       Reverse sort order.

Supported module sort keys:
  --modules                 : run,index,module,base,size,path,pid
  --modules-unique          : run,index,module,base,size,path,pid,snapshots,first_index,last_index
  --modules-presence        : module,runs,bases,paths,entries

Scope:
  The tool decodes selected Win32 structures and checks record coherence.
  CryptGenRandom records are displayed as opaque blobs: length, SHA-256,
  and first 16 bytes. They are not decoded as Win32 structures.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode, sort, compare, and validate randwin_full.json records.",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_argument_group("input")
    input_group.add_argument("input_path", help="path to randwin_full.json or to a directory of runs")
    input_group.add_argument("--recursive", action="store_true", help="search recursively for randwin_full.json files")

    output_group = parser.add_argument_group("general output")
    output_group.add_argument("--summary", action="store_true", help="print source/count summary")
    output_group.add_argument("--compare-sources", action="store_true", help="compare source presence/counts/bytes across runs")
    output_group.add_argument("--coherence", action="store_true", help="print source, module, blob, and validation coherence tables")
    output_group.add_argument("--source", help="decode or display only a selected source")
    output_group.add_argument("--limit", type=int, help="limit decoded or specialized output")
    output_group.add_argument("--grep", help="case-insensitive filter for specialized textual views")
    output_group.add_argument("--sort", help="sort key for supported specialized views; see examples below")
    output_group.add_argument("--desc", action="store_true", help="sort in descending order when --sort is used")
    output_group.add_argument("--aggregate", action="store_true", help="append aggregate tables after detailed views when supported")
    output_group.add_argument("--no-aggregate", action="store_true", help="compatibility option; suppress aggregate tables if --aggregate is also used")

    validation_group = parser.add_argument_group("validation")
    validation_group.add_argument("--validate", action="store_true", help="run structural and semantic validation")
    validation_group.add_argument("--json", action="store_true", help="emit validation result as JSON")

    view_group = parser.add_argument_group("specialized views")
    view_group.add_argument("--modules", action="store_true", help="print raw ModuleEntry records")
    view_group.add_argument("--modules-unique", action="store_true", help="print de-duplicated ModuleEntry records per run/module/base/path/pid")
    view_group.add_argument("--modules-presence", action="store_true", help="print module presence matrix only")
    view_group.add_argument("--processes", action="store_true", help="print ProcessEntry records")
    view_group.add_argument("--threads", action="store_true", help="print ThreadEntry records and owner counts")
    view_group.add_argument("--heaps", action="store_true", help="print Heap32List and Heap32Entry records")
    view_group.add_argument("--lanman", action="store_true", help="print LanmanWorkstation and LanmanServer records")
    view_group.add_argument("--memory", action="store_true", help="print GlobalMemoryStatus records")
    view_group.add_argument("--timing", action="store_true", help="print QPC, queue, foreground-window, and PID records")
    view_group.add_argument("--blobs", action="store_true", help="print opaque blob records by length, SHA-256, and preview")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runs = load_runs(Path(args.input_path), args.recursive)

    did_something = False
    exit_code = 0

    def section_break() -> None:
        if did_something:
            print()

    if args.summary:
        print_summary(runs)
        did_something = True

    if args.modules or args.modules_unique or args.modules_presence:
        section_break()
        print_modules(
            runs,
            args.grep,
            args.limit,
            unique=args.modules_unique,
            presence_only=args.modules_presence,
            sort_key=args.sort,
            desc=args.desc,
            aggregate=args.aggregate and not args.no_aggregate,
        )
        did_something = True

    if args.processes:
        section_break()
        print_processes(runs, args.grep, args.limit)
        did_something = True

    if args.threads:
        section_break()
        print_threads(runs, args.grep, args.limit)
        did_something = True

    if args.heaps:
        section_break()
        print_heaps(runs, args.grep, args.limit)
        did_something = True

    if args.lanman:
        section_break()
        print_lanman(runs, args.grep, args.limit)
        did_something = True

    if args.memory:
        section_break()
        print_memory(runs, args.grep, args.limit)
        did_something = True

    if args.timing:
        section_break()
        print_timing(runs, args.grep, args.limit)
        did_something = True

    if args.blobs:
        section_break()
        print_blobs(runs, args.source, args.grep, args.limit)
        did_something = True

    if args.compare_sources:
        section_break()
        print_compare_sources(runs)
        did_something = True

    if args.coherence:
        section_break()
        print_coherence(runs, args.grep)
        did_something = True

    if args.source and not args.blobs:
        section_break()
        print_decoded(runs, args.source, args.limit)
        did_something = True

    if args.validate:
        if did_something and not args.json:
            print()
        exit_code = run_validation(runs, args.json)
        did_something = True

    if not did_something:
        print_summary(runs)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
