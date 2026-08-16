#!/usr/bin/env python3
"""Validate one XP CryptGenRandom invocation from a single WinDbg log.

The checker is deliberately fail-closed: missing markers, unequal event counts,
or a missing 32-byte caller artifact make the overall result INCOMPLETE/FAIL.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


DUMP_MARKERS = {
    "ksec_entry": ("E2E_KSEC_OUT_ENTRY_100", 0x100),
    "ksec_after": ("E2E_KSEC_OUT_AFTER_GATHER_100", 0x100),
    "ksec_return": ("E2E_KSEC_OUT_PRE_RETURN_100", 0x100),
    "ioctl": ("E2E_ADVAPI_IOCTL_OUT_100", 0x100),
    "sys_before": ("E2E_SYSTEMFUNCTION036_OUT_BEFORE_20", 0x20),
    "sys_after": ("E2E_SYSTEMFUNCTION036_OUT_AFTER_20", 0x20),
    "rc4_state_before": ("E2E_ADVAPI_RC4_STATE_BEFORE_102", 0x102),
    "rc4_out_before": ("E2E_ADVAPI_RC4_OUT_BEFORE", 0x20),
    "rc4_state_after": ("E2E_ADVAPI_RC4_STATE_AFTER_102", 0x102),
    "rc4_out_after": ("E2E_ADVAPI_RC4_OUT_AFTER", 0x20),
    "provider_state_before": ("E2E_PROVIDER_STATE_BEFORE_20", 0x20),
    "provider_out_before": ("E2E_CGR_OUT_BEFORE", 0x20),
    "provider_raw": ("E2E_PROVIDER_SYSFUNC_RAW20", 0x20),
    "provider_mix": ("E2E_CGR_OUT_STILL_BEFORE", 0x20),
    "provider_aux": ("E2E_PROVIDER_AUX_FINAL_20", 0x20),
    "provider_out40": ("E2E_PROVIDER_OUT40_AFTER", 0x28),
    "provider_state_after": ("E2E_PROVIDER_STATE_AFTER_20", 0x20),
    "provider_return": ("E2E_CRYPTGENRANDOM_OUTPUT", 0x20),
    "provider_global_before": ("E2E_PROVIDER_GLOBAL_STATE_BEFORE_20", 0x20),
    "provider_global_final": ("E2E_PROVIDER_GLOBAL_STATE_FINAL_20", 0x20),
}


def parse_dump_line(line: str) -> bytes:
    match = re.match(r"^\s*[0-9a-fA-F`]{8,17}\s{2}(.+)$", line)
    if not match:
        return b""
    # WinDbg puts ASCII after two spaces.  The byte field occupies at most
    # 48 characters (16 bytes plus the central hyphen separator).
    byte_field = match.group(1)[:48].replace("-", " ")
    tokens = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?![0-9a-fA-F])", byte_field)
    return bytes(int(token, 16) for token in tokens)


def dumps_after_marker(text: str, marker: str, size: int) -> list[bytes]:
    lines = text.splitlines()
    results: list[bytes] = []
    target = f"[{marker}]"
    for index, line in enumerate(lines):
        if line.strip() != target:
            continue
        data = bytearray()
        for following in lines[index + 1 :]:
            row = parse_dump_line(following)
            if not row:
                if data:
                    break
                continue
            data.extend(row)
            if len(data) >= size:
                break
        results.append(bytes(data[:size]))
    return results


def lengths_from_log(text: str) -> list[int]:
    values: list[int] = []
    for section in text.split("[E2E_ADVAPI_RC4_PRGA_ENTRY]")[1:]:
        match = re.search(r"prga_len=([0-9a-fA-F]+)", section)
        if match:
            values.append(int(match.group(1), 16))
    return values


def provider_lengths_from_log(text: str) -> list[int]:
    values: list[int] = []
    for section in text.split("[E2E_PROVIDER_BEFORE_SYSTEMFUNCTION036]")[1:]:
        match = re.search(r"provider_ret=.*?cgr_len=([0-9a-fA-F]+)", section)
        if match:
            values.append(int(match.group(1), 16))
    return values


def rc4_ksa(key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return bytes(state) + b"\x00\x00"


def rc4_replay(state258: bytes, input_prefix: bytes, length: int) -> tuple[bytes, bytes]:
    state = list(state258[:256])
    i, j = state258[256], state258[257]
    output = bytearray()
    for offset in range(length):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        if offset < len(input_prefix):
            output.append(input_prefix[offset] ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output), bytes(state) + bytes((i, j))


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def add160_be(left: bytes, right: bytes, carry: int = 0) -> bytes:
    value = (int.from_bytes(left, "big") + int.from_bytes(right, "big") + carry) % (1 << 160)
    return value.to_bytes(20, "big")


def rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def sha1_compress_one(block: bytes) -> bytes:
    if len(block) != 64:
        raise ValueError("SHA-1 compression block must contain 64 bytes")
    initial = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    words = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 80):
        words.append(rol32(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1))
    a, b, c, d, e = initial
    for i in range(80):
        if i < 20:
            function, constant = (b & c) | ((~b) & d), 0x5A827999
        elif i < 40:
            function, constant = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            function, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            function, constant = b ^ c ^ d, 0xCA62C1D6
        temporary = (rol32(a, 5) + function + e + constant + words[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, rol32(b, 30), a, temporary
    return b"".join(((old + new) & 0xFFFFFFFF).to_bytes(4, "big") for old, new in zip(initial, (a, b, c, d, e)))


def provider_block(state_before: bytes, auxiliary: bytes) -> tuple[bytes, bytes]:
    xval_a = add160_be(state_before, auxiliary)
    out_a = sha1_compress_one(xval_a + b"\x00" * 44)
    state_a = add160_be(state_before, out_a, 1)
    xval_b = add160_be(state_a, auxiliary)
    out_b = sha1_compress_one(xval_b + b"\x00" * 44)
    state_after = add160_be(state_a, out_b, 1)
    return out_a + out_b, state_after


class Checks:
    def __init__(self) -> None:
        self.values: dict[str, bool] = {}
        self.notes: dict[str, str] = {}

    def add(self, name: str, value: bool, note: str = "") -> None:
        self.values[name] = bool(value)
        if note:
            self.notes[name] = note


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--caller-output", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    text = args.log.read_text(encoding="utf-8", errors="replace")
    observed = {name: dumps_after_marker(text, marker, size) for name, (marker, size) in DUMP_MARKERS.items()}
    lengths = lengths_from_log(text)
    provider_lengths = provider_lengths_from_log(text)
    checks = Checks()

    process_ids = re.findall(r"target_eprocess=([0-9a-fA-F]+)", text)
    target_eprocess = process_ids[0] if len(process_ids) == 2 and len(set(process_ids)) == 1 else None
    checks.add("single_target_eprocess", len(process_ids) == 2 and len(set(process_ids)) == 1,
               f"phase_values={process_ids}")
    final_section = text.split("[FULLCHAIN_CAPTURE_END]", 1)[-1]
    final_filters = re.findall(r"Match process data ([0-9a-fA-F]+)", final_section)
    checks.add("all_breakpoints_process_filtered",
               len(final_filters) == 32 and target_eprocess is not None
               and all(value.lower() == target_eprocess.lower() for value in final_filters),
               f"final_filtered_entries={len(final_filters)} values={sorted(set(final_filters))}")
    phase_markers = (
        "FULLCHAIN_PHASE1_BEFORE_RSAENH_LOAD",
        "FULLCHAIN_PHASE1_BREAKPOINTS_ARMED",
        "FULLCHAIN_PHASE2_RSAENH_MAPPED_BEFORE_INITIALIZATION",
        "FULLCHAIN_PHASE2_PROVIDER_BREAKPOINTS_ARMED",
        "E2E_PROVIDER_RUNTIME_CALL",
        "E2E_PROVIDER_RUNTIME_RETURN",
        "FULLCHAIN_CAPTURE_END",
    )
    for marker in phase_markers:
        checks.add(f"single_marker_{marker.lower()}", text.count(f"[{marker}]") == 1)
    checks.add("log_closed_cleanly", text.count("Closing open log file") == 1)

    ksec_names = ("ksec_entry", "ksec_after", "ksec_return", "ioctl")
    ksec_count = min((len(observed[name]) for name in ksec_names), default=0)
    checks.add("ksec_event_arrays_complete",
               ksec_count == 8 and all(len(observed[name]) == ksec_count for name in ksec_names),
               " ".join(f"{name}={len(observed[name])}" for name in ksec_names))
    for index in range(ksec_count):
        checks.add(f"ksec_ioctl_{index:02d}_byte_equality",
                   observed["ksec_after"][index] == observed["ksec_return"][index] == observed["ioctl"][index])

    rc4_count = min(len(observed["rc4_state_before"]), len(observed["rc4_state_after"]),
                    len(observed["rc4_out_before"]), len(observed["rc4_out_after"]), len(lengths))
    checks.add("rc4_event_arrays_complete", rc4_count == 10 and all(len(observed[name]) == rc4_count for name in
               ("rc4_state_before", "rc4_state_after", "rc4_out_before", "rc4_out_after")) and len(lengths) == rc4_count,
               f"count={rc4_count} lengths={lengths}")

    for index in range(min(ksec_count, rc4_count)):
        checks.add(f"ioctl_{index:02d}_replays_rc4_ksa",
                   rc4_ksa(observed["ioctl"][index]) == observed["rc4_state_before"][index])

    for index in range(rc4_count):
        output, state_after = rc4_replay(observed["rc4_state_before"][index], observed["rc4_out_before"][index], lengths[index])
        expected_output = output + observed["rc4_out_before"][index][lengths[index]:]
        checks.add(f"rc4_{index:02d}_output_replay", expected_output == observed["rc4_out_after"][index])
        checks.add(f"rc4_{index:02d}_state_replay", state_after == observed["rc4_state_after"][index])

    for index in range(ksec_count, rc4_count):
        predecessors = [prior for prior in range(index)
                        if observed["rc4_state_after"][prior] == observed["rc4_state_before"][index]]
        checks.add(f"rc4_{index:02d}_unique_prior_state_continuity", len(predecessors) == 1,
                   f"prior_events={predecessors}")

    useful_rc4 = [index for index, length in enumerate(lengths) if length > 0]
    system_count = min(len(observed["sys_before"]), len(observed["sys_after"]))
    checks.add("systemfunction_nonzero_rc4_counts_equal",
               len(observed["sys_before"]) == len(observed["sys_after"]) == len(useful_rc4) == 3,
               f"sys={system_count} useful_rc4={useful_rc4}")
    for system_index, rc4_index in enumerate(useful_rc4[:system_count]):
        checks.add(f"sysfunc_{system_index:02d}_input_equals_rc4_{rc4_index:02d}_input",
                   observed["sys_before"][system_index] == observed["rc4_out_before"][rc4_index])
        checks.add(f"sysfunc_{system_index:02d}_output_equals_rc4_{rc4_index:02d}_output",
                   observed["sys_after"][system_index] == observed["rc4_out_after"][rc4_index])

    provider_entry_names = ("provider_state_before", "provider_aux")
    provider_return_names = ("provider_out40", "provider_state_after")
    provider_count = min((len(observed[name]) for name in provider_entry_names), default=0)
    provider_return_count = min((len(observed[name]) for name in provider_return_names), default=0)
    full_fips_shape = (provider_count == provider_return_count == 4
                       and all(len(observed[name]) == 4
                               for name in provider_entry_names + provider_return_names))
    # During the pre-runtime provider bootstrap, B12 can execute once before it
    # is converted from a hardware execution breakpoint to the process-filtered
    # software breakpoint.  B13 still records that first return.  This yields
    # one leading return followed by three fully paired entry/return events.
    leading_return_shape = (provider_count == 3 and provider_return_count == 4
                            and all(len(observed[name]) == 3 for name in provider_entry_names)
                            and all(len(observed[name]) == 4 for name in provider_return_names))
    # The preferred acquisition disables the four provisional hardware
    # breakpoints before rsaenh is mapped, then recreates them as
    # process-filtered software breakpoints at the second harness barrier.
    # In that shape the pre-provider SystemFunction036 bootstrap remains in
    # the system trace, while the provider trace contains the two complete
    # post-barrier calls: provider initialization and the measured runtime
    # call.  Both entry/return pairs are complete and replayable.
    paired_provider_shape = (provider_count == provider_return_count == 2
                             and all(len(observed[name]) == 2
                                     for name in provider_entry_names + provider_return_names))
    checks.add("provider_fips_event_arrays_complete",
               full_fips_shape or leading_return_shape or paired_provider_shape,
               " ".join(f"{name}={len(observed[name])}"
                        for name in provider_entry_names + provider_return_names))
    mix_names = ("provider_out_before", "provider_raw", "provider_mix")
    mix_count = min((len(observed[name]) for name in mix_names), default=0)
    expected_mix_count = 2 if paired_provider_shape else 3
    checks.add("provider_mix_event_arrays_complete",
               mix_count == expected_mix_count
               and all(len(observed[name]) == mix_count for name in mix_names)
               and len(provider_lengths) == mix_count,
               " ".join(f"{name}={len(observed[name])}" for name in mix_names)
               + f" lengths={provider_lengths}")
    system_offset = len(observed["sys_after"]) - mix_count
    checks.add("provider_systemfunction_counts_equal",
               (mix_count == len(observed["sys_after"]) == 3)
               or (paired_provider_shape and mix_count == 2
                   and len(observed["sys_after"]) == 3 and system_offset == 1),
               f"provider_mix={mix_count} systemfunction={len(observed['sys_after'])} "
               f"leading_system_events={system_offset}")
    for index in range(mix_count):
        checks.add(f"provider_mix_{index:02d}_cgr_buffer_unchanged_by_sysfunc",
                   observed["provider_out_before"][index] == observed["provider_mix"][index])
        system_index = index + system_offset
        system_available = 0 <= system_index < len(observed["sys_after"])
        checks.add(f"provider_mix_{index:02d}_raw_equals_sysfunc_output",
                   system_available
                   and observed["provider_raw"][index][:20]
                   == observed["sys_after"][system_index][:20])
        mixed_length = min(provider_lengths[index], 20)
        padded_prefix = observed["provider_mix"][index][:mixed_length] + b"\x00" * (20 - mixed_length)
        auxiliary = xor_bytes(observed["provider_raw"][index][:20], padded_prefix)
        auxiliary_index = index + 1 if full_fips_shape else index
        available = auxiliary_index < len(observed["provider_aux"])
        checks.add(f"provider_mix_{index:02d}_aux_xor_into_fips_{index + 1:02d}",
                   available and auxiliary == observed["provider_aux"][auxiliary_index][:20])

    return_offset = 1 if leading_return_shape else 0
    for index in range(provider_count):
        state_before20 = observed["provider_state_before"][index][:20]
        auxiliary = observed["provider_aux"][index][:20]
        output40, state_after = provider_block(state_before20, auxiliary)
        return_index = index + return_offset
        return_available = (return_index < len(observed["provider_out40"])
                            and return_index < len(observed["provider_state_after"]))
        checks.add(f"provider_{return_index:02d}_out40_replay",
                   return_available and output40 == observed["provider_out40"][return_index])
        checks.add(f"provider_{return_index:02d}_state_replay",
                   return_available
                   and state_after == observed["provider_state_after"][return_index][:20])
        if index + 1 < provider_count:
            checks.add(f"provider_{return_index:02d}_to_{return_index + 1:02d}_state_continuity",
                       return_available
                       and observed["provider_state_after"][return_index][:20]
                       == observed["provider_state_before"][index + 1][:20])
    if leading_return_shape:
        # B13's first hit precedes the first B12 hit, so its saved $t11/$t13
        # register aliases have no paired entry context.  Treat it only as the
        # single, explicitly accounted-for bootstrap return; all three later
        # B12/B13 pairs are replayed byte-for-byte above.
        checks.add("single_unpaired_provider_bootstrap_return",
                   provider_return_count - provider_count == 1,
                   "excluded_leading_returns=1; paired_provider_events=3")

    checks.add("single_provider_runtime_return", len(observed["provider_return"]) == 1)
    if provider_return_count >= 1 and len(observed["provider_return"]) == 1:
        checks.add("provider_runtime_return_equals_final_out40_prefix",
                   observed["provider_return"][0] == observed["provider_out40"][-1][:32])
    else:
        checks.add("provider_runtime_return_equals_final_out40_prefix", False)
    checks.add("single_provider_global_state_pair",
               len(observed["provider_global_before"]) == len(observed["provider_global_final"]) == 1)
    if (provider_count >= 1 and provider_return_count >= 1
            and len(observed["provider_global_before"]) == len(observed["provider_global_final"]) == 1):
        checks.add("provider_runtime_global_before_equals_final_fips_input",
                   observed["provider_global_before"][0][:20] == observed["provider_state_before"][-1][:20])
        checks.add("provider_runtime_global_final_equals_final_fips_state",
                   observed["provider_global_final"][0][:20] == observed["provider_state_after"][-1][:20])
    else:
        checks.add("provider_runtime_global_before_equals_final_fips_input", False)
        checks.add("provider_runtime_global_final_equals_final_fips_state", False)

    caller = args.caller_output.read_bytes() if args.caller_output and args.caller_output.exists() else b""
    checks.add("caller_artifact_exactly_32_bytes", len(caller) == 32, f"size={len(caller)}")
    if len(observed["provider_return"]) == 1 and len(caller) == 32:
        checks.add("caller_artifact_equals_final_provider_return", caller == observed["provider_return"][0])
    else:
        checks.add("caller_artifact_equals_final_provider_return", False)

    overall = bool(checks.values) and all(checks.values.values())
    status = "PASS" if overall else "INCOMPLETE_OR_FAIL"

    print(f"[STRICT_E2E] {status}")
    print(f"target_eprocess={target_eprocess or 'UNPROVEN'}")
    print(f"events: ksec={ksec_count} ioctl={len(observed['ioctl'])} rc4={rc4_count} "
          f"sysfunc={system_count} provider_fips={provider_count} provider_mix={mix_count}")
    for name, value in checks.values.items():
        note = f" ({checks.notes[name]})" if name in checks.notes else ""
        print(f"{'PASS' if value else 'FAIL':4} {name}{note}")

    report = {
        "status": status,
        "overall": overall,
        "source_log": str(args.log),
        "caller_output": str(args.caller_output) if args.caller_output else None,
        "target_eprocess": target_eprocess,
        "event_counts": {name: len(values) for name, values in observed.items()},
        "prga_lengths": lengths,
        "provider_lengths": provider_lengths,
        "checks": checks.values,
        "notes": checks.notes,
        "final_output_hex": caller.hex() if caller else None,
    }
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
