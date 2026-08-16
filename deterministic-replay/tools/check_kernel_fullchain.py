#!/usr/bin/env python3
"""Replay the XP KSecDD collector, mixer, and RC4 path from WinDbg dumps.

This validator is deliberately fail-closed.  It validates only the kernel and
immediate ADVAPI boundary.  The caller/provider half remains the responsibility
of check_strict_e2e.py, run against the same journal and caller artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STRICT_SPEC = importlib.util.spec_from_file_location(
    "strict_e2e_helpers", ROOT / "check_strict_e2e.py"
)
if STRICT_SPEC is None or STRICT_SPEC.loader is None:
    raise RuntimeError("cannot load check_strict_e2e.py")
STRICT = importlib.util.module_from_spec(STRICT_SPEC)
STRICT_SPEC.loader.exec_module(STRICT)


DUMPS = {
    "ksec_entry": ("E2E_KSEC_OUT_ENTRY_100", 0x100),
    "state_before": ("FULLCHAIN_STATE_BEFORE_50", 0x50),
    "workspace": ("FULLCHAIN_WORKSPACE_PRE_MIX_E00", 0xE00),
    "state_after": ("FULLCHAIN_STATE_AFTER_MIX_50", 0x50),
    "old_state_rc4": ("FULLCHAIN_OLD_STATE_RC4_AFTER_50", 0x50),
    "old_state_context": ("FULLCHAIN_RC4_CONTEXT_AFTER_OLD_STATE_102", 0x102),
    "final_context": ("FULLCHAIN_FINAL_RC4_CONTEXT_102", 0x102),
    "global_state": ("FULLCHAIN_GLOBAL_STATE_50", 0x50),
    "final_output": ("FULLCHAIN_FINAL_RC4_OUTPUT", 0x100),
    "ksec_after": ("E2E_KSEC_OUT_AFTER_GATHER_100", 0x100),
    "ksec_return": ("E2E_KSEC_OUT_PRE_RETURN_100", 0x100),
    "ioctl": ("E2E_ADVAPI_IOCTL_OUT_100", 0x100),
    "pid": ("FULLCHAIN_PROCESS_ID_APPENDED", 0x08),
    "tid": ("FULLCHAIN_THREAD_ID_APPENDED", 0x08),
    "tick": ("FULLCHAIN_TICK_COUNT_APPENDED", 0x10),
    "cpu": ("FULLCHAIN_CPU_COUNTERS_RETURN", 0x40),
    "raw05": ("FULLCHAIN_SYSINFO_05_RAW", 0xE00),
    "raw08": ("FULLCHAIN_SYSINFO_08_RAW", 0xE00),
    "raw17": ("FULLCHAIN_SYSINFO_17_RAW", 0xE00),
}

META_MARKERS = {
    "alloc": "FULLCHAIN_COLLECTOR_ALLOCATED",
    "pid": "FULLCHAIN_PROCESS_ID_APPENDED",
    "tid": "FULLCHAIN_THREAD_ID_APPENDED",
    "tick": "FULLCHAIN_TICK_COUNT_APPENDED",
    "cpu": "FULLCHAIN_CPU_COUNTERS_RETURN",
    "sys05": "FULLCHAIN_SYSINFO_05_RAW",
    "sys03": "FULLCHAIN_SYSINFO_03_RETURN",
    "sys07": "FULLCHAIN_SYSINFO_07_RETURN",
    "sys02": "FULLCHAIN_SYSINFO_02_RETURN",
    "sys21": "FULLCHAIN_SYSINFO_21_RETURN",
    "sys2d": "FULLCHAIN_SYSINFO_2D_RETURN",
    "sys08": "FULLCHAIN_SYSINFO_08_RAW",
    "sys17": "FULLCHAIN_SYSINFO_17_RAW",
    "premix": "FULLCHAIN_PRE_MIX",
    "final": "FULLCHAIN_FINAL_RC4_OUTPUT",
}


class Checks:
    def __init__(self) -> None:
        self.values: dict[str, bool] = {}
        self.notes: dict[str, str] = {}

    def add(self, name: str, value: bool, note: str = "") -> None:
        self.values[name] = bool(value)
        if note:
            self.notes[name] = note


def marker_sections(text: str, marker: str) -> list[str]:
    lines = text.splitlines()
    target = f"[{marker}]"
    sections: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() != target:
            continue
        body: list[str] = []
        for following in lines[index + 1 :]:
            if re.match(r"^\[[A-Za-z0-9_]+\]$", following.strip()):
                break
            body.append(following)
        sections.append("\n".join(body))
    return sections


def hex_field(section: str, name: str) -> int | None:
    match = re.search(rf"(?:^|\s){re.escape(name)}=([0-9a-fA-F]+)(?:\s|$)", section)
    return int(match.group(1), 16) if match else None


def align8(value: int) -> int:
    return (value + 7) & ~7


def rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def sha1_compress(state: tuple[int, ...], block: bytes, endian: str) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("SHA-1 block must contain 64 bytes")
    words = [int.from_bytes(block[offset : offset + 4], endian)
             for offset in range(0, 64, 4)]
    for index in range(16, 80):
        words.append(rol32(words[index - 3] ^ words[index - 8]
                           ^ words[index - 14] ^ words[index - 16], 1))
    a, b, c, d, e = state
    for index in range(80):
        if index < 20:
            function = (b & c) | ((~b) & d)
            constant = 0x5A827999
        elif index < 40:
            function = b ^ c ^ d
            constant = 0x6ED9EBA1
        elif index < 60:
            function = (b & c) | (b & d) | (c & d)
            constant = 0x8F1BBCDC
        else:
            function = b ^ c ^ d
            constant = 0xCA62C1D6
        temporary = (rol32(a, 5) + function + e + constant + words[index]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, rol32(b, 30), a, temporary
    return tuple((old + new) & 0xFFFFFFFF
                 for old, new in zip(state, (a, b, c, d, e)))


def ksec_mixer_hash(message: bytes) -> bytes:
    """Reproduce ksecdd!f745f540/f745f610, including its byte order.

    Complete data blocks are compressed as native little-endian DWORDs by the
    dedicated update routine.  The final buffered block goes through the
    regular big-endian SHA-1 transform, while the five state DWORDs are copied
    to the result in native little-endian order.  This is intentionally not
    interchangeable with hashlib.sha1().
    """

    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    complete = len(message) // 64
    for index in range(complete):
        state = sha1_compress(state, message[index * 64 : (index + 1) * 64], "little")
    remainder = message[complete * 64 :]
    padding_length = 64 - (len(message) & 0x3F)
    if padding_length <= 8:
        padding_length += 64
    bit_length = len(message) * 8
    padding = (b"\x80" + bytes(padding_length - 9)
               + (bit_length >> 32).to_bytes(4, "little")
               + (bit_length & 0xFFFFFFFF).to_bytes(4, "little"))
    final_blocks = remainder + padding
    if len(final_blocks) % 64:
        raise AssertionError("internal padding error")
    for offset in range(0, len(final_blocks), 64):
        state = sha1_compress(state, final_blocks[offset : offset + 64], "big")
    return b"".join(word.to_bytes(4, "little") for word in state)


def replay_mixer(workspace: bytes, used: int, old_state: bytes) -> bytes:
    data = workspace[:used]
    quarter = used // 4
    quarters = [data[index * quarter : (index + 1) * quarter] for index in range(4)]
    states = [old_state[index * 20 : (index + 1) * 20] for index in range(4)]
    digest_a = ksec_mixer_hash(states[0] + quarters[0] + states[1] + quarters[1])
    digest_b = ksec_mixer_hash(states[1] + quarters[1] + states[0] + quarters[0])
    digest_c = ksec_mixer_hash(states[2] + quarters[2] + states[3] + quarters[3])
    digest_d = ksec_mixer_hash(states[3] + quarters[3] + states[2] + quarters[2])
    return (ksec_mixer_hash(digest_a + digest_c)
            + ksec_mixer_hash(digest_b + digest_d)
            + ksec_mixer_hash(digest_c + digest_a)
            + ksec_mixer_hash(digest_d + digest_b))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--expected-events", type=int, default=8)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    text = args.log.read_text(encoding="utf-8", errors="replace")
    observed = {
        name: STRICT.dumps_after_marker(text, marker, size)
        for name, (marker, size) in DUMPS.items()
    }
    metadata = {name: marker_sections(text, marker) for name, marker in META_MARKERS.items()}
    checks = Checks()

    required_arrays = tuple(DUMPS)
    counts = {name: len(values) for name, values in observed.items()}
    event_count = min(counts.values(), default=0)
    checks.add(
        "all_kernel_event_arrays_complete",
        event_count == args.expected_events
        and all(counts[name] == args.expected_events for name in required_arrays)
        and all(len(metadata[name]) == args.expected_events for name in metadata),
        f"expected={args.expected_events} dumps={counts} meta="
        + str({name: len(values) for name, values in metadata.items()}),
    )

    for index in range(event_count):
        prefix = f"event_{index:02d}"
        base = hex_field(metadata["alloc"][index], "collector_base")
        used = hex_field(metadata["premix"][index], "used")
        output_length = hex_field(metadata["final"][index], "output_len")
        checks.add(f"{prefix}_metadata_present",
                   base is not None and used is not None and output_length is not None)
        if base is None or used is None or output_length is None:
            continue
        checks.add(f"{prefix}_used_range", 0 < used <= 0xE00 and used % 4 == 0,
                   f"used=0x{used:x}")
        checks.add(f"{prefix}_output_length_256", output_length == 0x100,
                   f"output_len=0x{output_length:x}")

        workspace = observed["workspace"][index]
        source_offsets: dict[str, int] = {}
        reported: dict[str, int] = {}
        statuses: dict[str, int] = {}
        for name in ("pid", "tid", "tick", "cpu", "sys05", "sys03", "sys07",
                     "sys02", "sys21", "sys2d", "sys08", "sys17"):
            source = hex_field(metadata[name][index], "source_start")
            length = hex_field(metadata[name][index], "reported_len")
            status = hex_field(metadata[name][index], "status")
            if source is not None:
                source_offsets[name] = source - base
            if length is not None:
                reported[name] = length
            if status is not None:
                statuses[name] = status

        expected_sources = {
            "pid": 0x08,
            "tid": 0x10,
            "tick": 0x18,
            "cpu": 0x28,
        }
        if "cpu" in reported:
            expected_sources["sys05"] = expected_sources["cpu"] + align8(reported["cpu"] + 8)
        if "sys05" in expected_sources:
            expected_sources["sys03"] = expected_sources["sys05"] + 0x18
        for previous, following in (("sys03", "sys07"), ("sys07", "sys02"),
                                    ("sys02", "sys21"), ("sys21", "sys2d"),
                                    ("sys2d", "sys08")):
            if previous in expected_sources and previous in reported:
                # Successful fixed-size queries retain their raw bytes and an
                # eight-byte aligned reservation in the collector workspace.
                expected_sources[following] = expected_sources[previous] + align8(reported[previous] + 8)
        if "sys08" in expected_sources:
            expected_sources["sys17"] = expected_sources["sys08"] + 0x18
        checks.add(f"{prefix}_collector_layout",
                   all(source_offsets.get(name) == offset for name, offset in expected_sources.items()),
                   f"observed={source_offsets} expected={expected_sources}")
        if "sys17" in source_offsets:
            checks.add(f"{prefix}_used_matches_final_digest_reservation",
                       used == source_offsets["sys17"] + 0x18,
                       f"used=0x{used:x} final_source=0x{source_offsets['sys17']:x}")

        for name, dump_name, source_name, compare_length in (
            ("pid", "pid", "pid", 8),
            ("tid", "tid", "tid", 8),
            ("tick", "tick", "tick", 16),
        ):
            offset = source_offsets.get(source_name)
            checks.add(f"{prefix}_{name}_bytes_in_workspace",
                       offset is not None
                       and observed[dump_name][index][:compare_length]
                       == workspace[offset : offset + compare_length])
        cpu_offset = source_offsets.get("cpu")
        cpu_length = reported.get("cpu")
        checks.add(f"{prefix}_cpu_bytes_in_workspace",
                   cpu_offset is not None and cpu_length is not None
                   and 0 <= cpu_length <= 0x40
                   and observed["cpu"][index][:cpu_length]
                   == workspace[cpu_offset : cpu_offset + cpu_length],
                   f"reported_len={cpu_length}")

        for source_name, dump_name in (("sys05", "raw05"),
                                       ("sys08", "raw08"),
                                       ("sys17", "raw17")):
            offset = source_offsets.get(source_name)
            length = reported.get(source_name)
            raw_dump = observed[dump_name][index]
            valid = (offset is not None and length is not None and offset >= 0
                     and offset + length <= len(raw_dump) and offset + 20 <= len(workspace))
            digest = hashlib.sha1(raw_dump[offset : offset + length]).digest() if valid else b""
            checks.add(f"{prefix}_{source_name}_raw_sha1_into_workspace",
                       valid and digest == workspace[offset : offset + 20],
                       f"offset={offset} reported_len={length} status={statuses.get(source_name)}")

        old_state = observed["state_before"][index]
        new_state = observed["state_after"][index]
        replayed_state = replay_mixer(workspace, used, old_state)
        checks.add(f"{prefix}_mixer_state_replay", replayed_state == new_state)
        checks.add(f"{prefix}_global_state_commit",
                   observed["global_state"][index] == new_state)

        initial_old_context = STRICT.rc4_ksa(old_state)
        old_ciphertext, old_context_after = STRICT.rc4_replay(
            initial_old_context, new_state, len(new_state)
        )
        checks.add(f"{prefix}_old_state_rc4_side_effect_replay",
                   old_ciphertext == observed["old_state_rc4"][index])
        checks.add(f"{prefix}_old_state_rc4_context_replay",
                   old_context_after == observed["old_state_context"][index])

        final_context = STRICT.rc4_ksa(new_state)
        checks.add(f"{prefix}_final_rc4_ksa_replay",
                   final_context == observed["final_context"][index])
        final_output, _ = STRICT.rc4_replay(
            final_context, observed["ksec_entry"][index], output_length
        )
        checks.add(f"{prefix}_final_rc4_output_replay",
                   final_output == observed["final_output"][index])
        checks.add(f"{prefix}_kernel_to_ioctl_byte_equality",
                   observed["final_output"][index]
                   == observed["ksec_after"][index]
                   == observed["ksec_return"][index]
                   == observed["ioctl"][index])

    overall = bool(checks.values) and all(checks.values.values())
    status = "PASS_KERNEL_STAGE" if overall else "INCOMPLETE_OR_FAIL"
    print(f"[KERNEL_FULLCHAIN] {status}")
    print(f"events={event_count} expected={args.expected_events}")
    for name, value in checks.values.items():
        note = f" ({checks.notes[name]})" if name in checks.notes else ""
        print(f"{'PASS' if value else 'FAIL':4} {name}{note}")

    result = {
        "status": status,
        "overall": overall,
        "scope": "KSecDD collector through ADVAPI IOCTL boundary",
        "source_log": str(args.log),
        "expected_events": args.expected_events,
        "observed_events": event_count,
        "event_counts": counts,
        "checks": checks.values,
        "notes": checks.notes,
    }
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
