#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, struct, sys
from pathlib import Path

MAGIC = b"CGRMSV2\0"
VERSION = 2
EXPECTED_SIZE = 9468


def must(b: bytes, n: int, label: str) -> bytes:
    if len(b) != n:
        raise SystemExit(f"{label}: expected {n}, got {len(b)}")
    return b


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package-root", type=Path, required=True)
    ap.add_argument("--run", default="run1")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    root = a.package_root.resolve()
    bundle_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(bundle_root / "oracle"))
    import model  # type: ignore

    rd = root / "fixtures" / a.run
    state = json.loads((rd / "state_before.json").read_text(encoding="utf-8"))
    src = json.loads((rd / "sources.json").read_text(encoding="utf-8"))
    obs_path = rd / "observed.json"
    obs = json.loads(obs_path.read_text(encoding="utf-8")) if obs_path.exists() else None
    model.validate_sources(src)
    if state.get("boundary") != "pre_acquisition":
        raise SystemExit("requires pre_acquisition state")

    ev0, ev1 = src["ksec_events"][:2]
    p0 = must(model.build_pool(ev0), 600, "pool0")
    p1 = must(model.build_pool(ev1), 600, "pool1")
    ksec = must(bytes.fromhex(state["ksec_global_state_hex"]), 80, "ksec_global")
    fips = must(bytes.fromhex(state["provider_fips_state_hex"]), 20, "fips")
    b0 = must(bytes.fromhex(ev0["ksec_output_before_hex"]), 256, "before0")
    b1 = must(bytes.fromhex(ev1["ksec_output_before_hex"]), 256, "before1")
    q050 = must(bytes.fromhex(ev0["sources"]["qsi05"]), 0xDC8, "qsi05_0")
    q051 = must(bytes.fromhex(ev1["sources"]["qsi05"]), 0xDC8, "qsi05_1")
    q080 = must(bytes.fromhex(ev0["sources"]["qsi08"]), 0xC0, "qsi08_0")
    q081 = must(bytes.fromhex(ev1["sources"]["qsi08"]), 0xC0, "qsi08_1")
    sysb = [must(bytes.fromhex(x), 32, f"sys{i}") for i, x in enumerate(src["systemfunction_inputs_hex"])]
    calls = src["provider_calls"]
    callers = [must(bytes.fromhex(c["caller_buffer_before_hex"]), 32, f"caller{i}") for i, c in enumerate(calls)]
    lens = [int(c["length"]) for c in calls]
    requested = int(src["requested_output_length"])
    historical = {
        "run1": "a37bf2d7c0c473fc92c62f5171adb25cabdb23a5bb9fcc6b3bd733aaeac53ad4",
        "run2": "73f3bee078d1335c3dda75994b505be400b1b29ecf2443000cf83128dfcd2fd8",
    }
    expected_hex = obs["output_hex"] if obs is not None else historical.get(a.run)
    if expected_hex is None:
        raise SystemExit(f"no observed.json and no historical output registered for {a.run}")
    expected = must(bytes.fromhex(expected_hex), 32, "expected")

    raw = b"".join([
        MAGIC, struct.pack("<I", VERSION),
        ksec, fips, p0, p1, b0, b1,
        q050, q051, q080, q081,
        *sysb, *callers,
        struct.pack("<III", lens[0], lens[1], requested), expected,
    ])
    if len(raw) != EXPECTED_SIZE:
        raise SystemExit(f"fixture ABI mismatch: {len(raw)} != {EXPECTED_SIZE}")

    # Independent baseline check through the Python oracle.
    pred = model.predict(state, src)
    actual = bytes.fromhex(pred["predicted_output_hex"])
    if actual != expected:
        raise SystemExit(f"baseline mismatch expected={expected.hex()} predicted={actual.hex()}")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_bytes(raw)
    print(f"MULTISOURCE_FIXTURE PASS run={a.run} bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()} expected={expected.hex()} out={a.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
