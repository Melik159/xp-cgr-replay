#!/usr/bin/env python3
"""Versioned state serialization for the reconstructed XP CGR model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "cgr-provider-state/v1"


def _hex_bytes(value: Any, size: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: expected hexadecimal string")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field}: invalid hexadecimal string") from exc
    if len(data) != size:
        raise ValueError(f"{field}: expected {size} bytes, got {len(data)}")
    return data


def validate_state(state: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        raise ValueError(f"state schema must be {SCHEMA}")
    boundary = state.get("boundary")
    if boundary == "pre_acquisition":
        _hex_bytes(state.get("ksec_global_state_hex"), 80, "ksec_global_state_hex")
        _hex_bytes(state.get("provider_fips_state_hex"), 20, "provider_fips_state_hex")
        required = {"schema", "boundary", "ksec_global_state_hex", "provider_fips_state_hex"}
    elif boundary == "pre_runtime":
        _hex_bytes(state.get("rc4_context_hex"), 258, "rc4_context_hex")
        _hex_bytes(state.get("provider_fips_state_hex"), 20, "provider_fips_state_hex")
        required = {"schema", "boundary", "rc4_context_hex", "provider_fips_state_hex"}
    elif boundary == "post_runtime":
        _hex_bytes(state.get("provider_fips_state_hex"), 20, "provider_fips_state_hex")
        contexts = state.get("rc4_contexts_hex")
        if not isinstance(contexts, list) or not contexts:
            raise ValueError("rc4_contexts_hex: expected non-empty list")
        for index, value in enumerate(contexts):
            _hex_bytes(value, 258, f"rc4_contexts_hex[{index}]")
        required = {"schema", "boundary", "provider_fips_state_hex", "rc4_contexts_hex"}
        if "ksec_global_state_hex" in state:
            _hex_bytes(state["ksec_global_state_hex"], 80, "ksec_global_state_hex")
            required.add("ksec_global_state_hex")
    else:
        raise ValueError(f"unsupported state boundary: {boundary!r}")
    extra = set(state) - required
    if extra:
        raise ValueError(f"undocumented state fields: {sorted(extra)}")
    return state


def load_state(path: str | Path) -> dict[str, Any]:
    state = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_state(state)


def save_state(path: str | Path, state: dict[str, Any]) -> None:
    validate_state(state)
    Path(path).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

