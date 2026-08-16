#!/usr/bin/env python3
"""Pure deterministic reconstruction of the captured XP CGR path."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

VENDOR = Path(__file__).resolve().parent / "vendor"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))

import check_kernel_fullchain as kernel  # noqa: E402
import check_strict_e2e as strict  # noqa: E402
from provider_state import SCHEMA, validate_state  # noqa: E402

SOURCE_SCHEMA = "cgr-source-inputs/v1"
PREDICTION_SCHEMA = "cgr-prediction/v1"

SOURCE_SIZES = {
    "allocator": 0x08, "pid": 0x08, "tid": 0x08, "tick": 0x10,
    "cpu": 0x40, "qsi05": 0xDC8, "qsi03": 0x38, "qsi07": 0x20,
    "qsi02": 0x140, "qsi21": 0x18, "qsi2d": 0x28,
    "qsi08": 0xC0, "qsi17": 0x18,
}

LAYOUT = {
    "pid": (0x008, 0x04, 0x08, "copy"),
    "tid": (0x010, 0x04, 0x08, "copy"),
    "tick": (0x018, 0x08, 0x10, "copy"),
    "cpu": (0x028, 0x08, 0x10, "copy"),
    "qsi05": (0x038, 0xDC8, 0x18, "sha1"),
    "qsi03": (0x050, 0x30, 0x38, "copy"),
    "qsi07": (0x088, 0x18, 0x20, "copy"),
    "qsi02": (0x0A8, 0x138, 0x140, "copy"),
    "qsi21": (0x1E8, 0x10, 0x18, "copy"),
    "qsi2d": (0x200, 0x20, 0x28, "copy"),
    "qsi08": (0x228, 0xC0, 0x18, "sha1"),
    "qsi17": (0x240, 0x00, 0x18, "sha1"),
}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _decode(value: Any, size: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: expected hex string")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field}: invalid hex") from exc
    if len(data) != size:
        raise ValueError(f"{field}: expected {size} bytes, got {len(data)}")
    return data


def validate_sources(sources: dict[str, Any]) -> dict[str, Any]:
    if sources.get("schema") != SOURCE_SCHEMA:
        raise ValueError(f"sources schema must be {SOURCE_SCHEMA}")
    events = sources.get("ksec_events")
    if not isinstance(events, list) or len(events) != 8:
        raise ValueError("ksec_events: expected exactly 8 events")
    for index, event in enumerate(events):
        fields = event.get("sources") if isinstance(event, dict) else None
        if not isinstance(fields, dict) or set(fields) != set(SOURCE_SIZES):
            raise ValueError(f"ksec_events[{index}].sources: wrong fields")
        for name, size in SOURCE_SIZES.items():
            _decode(fields[name], size, f"ksec_events[{index}].sources.{name}")
        _decode(event.get("ksec_output_before_hex"), 256,
                f"ksec_events[{index}].ksec_output_before_hex")
    system_inputs = sources.get("systemfunction_inputs_hex")
    if not isinstance(system_inputs, list) or len(system_inputs) != 3:
        raise ValueError("systemfunction_inputs_hex: expected 3 buffers")
    for index, value in enumerate(system_inputs):
        _decode(value, 32, f"systemfunction_inputs_hex[{index}]")
    calls = sources.get("provider_calls")
    if not isinstance(calls, list) or [c.get("length") for c in calls] != [10, 32]:
        raise ValueError("provider_calls: expected lengths [10, 32]")
    for index, call in enumerate(calls):
        _decode(call.get("caller_buffer_before_hex"), 32,
                f"provider_calls[{index}].caller_buffer_before_hex")
    allowed = {"schema", "ksec_events", "systemfunction_inputs_hex", "provider_calls", "requested_output_length"}
    if set(sources) - allowed:
        raise ValueError(f"undocumented source fields: {sorted(set(sources) - allowed)}")
    if sources.get("requested_output_length") != 32:
        raise ValueError("requested_output_length must be 32 for this campaign")
    return sources


def build_pool(event: dict[str, Any]) -> bytes:
    fields = {name: bytes.fromhex(value) for name, value in event["sources"].items()}
    pool = bytearray(0x258)
    pool[:8] = fields["allocator"]
    for name, (offset, payload_len, reserved_len, transform) in LAYOUT.items():
        data = fields[name]
        if transform == "copy":
            pool[offset:offset + reserved_len] = data[:reserved_len]
        else:
            pool[offset:offset + 20] = hashlib.sha1(data[:payload_len]).digest()
            pool[offset + 20:offset + reserved_len] = data[20:reserved_len]
    return bytes(pool)


def _provider_call(context: bytes, fips_state: bytes, sys_input: bytes,
                   caller_before: bytes, length: int) -> tuple[bytes, bytes, bytes, bytes]:
    raw, context_after = strict.rc4_replay(context, sys_input, 20)
    mixed = caller_before[:min(length, 20)] + bytes(20 - min(length, 20))
    auxiliary = strict.xor_bytes(raw[:20], mixed)
    out40, fips_after = strict.provider_block(fips_state, auxiliary)
    return out40, fips_after, context_after, auxiliary


def predict_full(state: dict[str, Any], sources: dict[str, Any]) -> dict[str, Any]:
    validate_state(state)
    validate_sources(sources)
    if state["boundary"] != "pre_acquisition":
        raise ValueError("predict_full requires pre_acquisition state")
    ksec_state = bytes.fromhex(state["ksec_global_state_hex"])
    fips_state = bytes.fromhex(state["provider_fips_state_hex"])
    sys_inputs = [bytes.fromhex(value) for value in sources["systemfunction_inputs_hex"]]
    contexts: list[bytes] = []
    pool_hashes: list[str] = []
    for index, event in enumerate(sources["ksec_events"]):
        pool = build_pool(event)
        pool_hashes.append(hashlib.sha256(pool).hexdigest())
        ksec_state = kernel.replay_mixer(pool, len(pool), ksec_state)
        ksec_context = strict.rc4_ksa(ksec_state)
        ksec_output, _ = strict.rc4_replay(
            ksec_context, bytes.fromhex(event["ksec_output_before_hex"]), 256)
        context = strict.rc4_ksa(ksec_output)
        if index == 0:
            _, context = strict.rc4_replay(context, sys_inputs[0], 20)
        contexts.append(context)

    calls = sources["provider_calls"]
    init_out, fips_state, contexts[0], init_aux = _provider_call(
        contexts[0], fips_state, sys_inputs[1],
        bytes.fromhex(calls[0]["caller_buffer_before_hex"]), calls[0]["length"])
    runtime_out, fips_state, contexts[1], runtime_aux = _provider_call(
        contexts[1], fips_state, sys_inputs[2],
        bytes.fromhex(calls[1]["caller_buffer_before_hex"]), calls[1]["length"])
    requested = sources["requested_output_length"]
    post_state = {
        "schema": SCHEMA,
        "boundary": "post_runtime",
        "ksec_global_state_hex": ksec_state.hex(),
        "rc4_contexts_hex": [value.hex() for value in contexts],
        "provider_fips_state_hex": fips_state.hex(),
    }
    validate_state(post_state)
    return {
        "schema": PREDICTION_SCHEMA,
        "model_boundary": "pre_acquisition",
        "input_digest_sha256": canonical_hash({"state": state, "sources": sources}),
        "predicted_output_hex": runtime_out[:requested].hex(),
        "predicted_state_after": post_state,
        "intermediate": {
            "source_pool_sha256": pool_hashes,
            "provider_initialization_out40_hex": init_out.hex(),
            "provider_initialization_aux_hex": init_aux.hex(),
            "provider_runtime_out40_hex": runtime_out.hex(),
            "provider_runtime_aux_hex": runtime_aux.hex(),
        },
    }


def predict_runtime(state: dict[str, Any], sources: dict[str, Any]) -> dict[str, Any]:
    validate_state(state)
    validate_sources(sources)
    if state["boundary"] != "pre_runtime":
        raise ValueError("predict_runtime requires pre_runtime state")
    call = sources["provider_calls"][1]
    out40, fips_after, context_after, auxiliary = _provider_call(
        bytes.fromhex(state["rc4_context_hex"]),
        bytes.fromhex(state["provider_fips_state_hex"]),
        bytes.fromhex(sources["systemfunction_inputs_hex"][2]),
        bytes.fromhex(call["caller_buffer_before_hex"]), call["length"])
    post_state = {
        "schema": SCHEMA,
        "boundary": "post_runtime",
        "rc4_contexts_hex": [context_after.hex()],
        "provider_fips_state_hex": fips_after.hex(),
    }
    return {
        "schema": PREDICTION_SCHEMA,
        "model_boundary": "pre_runtime",
        "input_digest_sha256": canonical_hash({"state": state, "sources": sources}),
        "predicted_output_hex": out40[:sources["requested_output_length"]].hex(),
        "predicted_state_after": post_state,
        "intermediate": {"provider_runtime_out40_hex": out40.hex(),
                         "provider_runtime_aux_hex": auxiliary.hex()},
    }


def predict(state: dict[str, Any], sources: dict[str, Any]) -> dict[str, Any]:
    return predict_full(copy.deepcopy(state), copy.deepcopy(sources)) if state.get("boundary") == "pre_acquisition" else predict_runtime(copy.deepcopy(state), copy.deepcopy(sources))
