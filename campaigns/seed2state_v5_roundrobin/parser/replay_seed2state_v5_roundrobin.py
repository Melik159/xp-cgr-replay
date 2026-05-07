#!/usr/bin/env python3
"""
replay_seed2state_v5_roundrobin.py

Offline verifier/replayer for the seed2state_v5_roundrobin JSON output.

It verifies the part now captured in v5:

    VLH seedbase_after -> LSA slot
    KSecDD RC4_2 output -> ADVAPI IOCTL buffer 0x100
    ADVAPI rc4_safe_select -> rc4_safe -> rc4 PRGA
    RC4 PRGA output -> SystemFunction036 output20
    SystemFunction036 output20 -> rsaenh aux20

Important scope:
    This script replays the ADVAPI32 RC4 PRGA exactly from the captured state.
    It does NOT reconstruct the ADVAPI32 rekey/KSA from the IOCTL buffer.
    That remains the next residual subproblem.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def hx(s: Optional[str]) -> bytes:
    if not s:
        return b""
    s = "".join(str(s).split()).lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        raise ValueError(f"Odd-length hex string: {s[:32]}...")
    return bytes.fromhex(s)


def hxd(b: bytes, group: int = 16) -> str:
    return " ".join(b[i:i + group].hex() for i in range(0, len(b), group))


def u32_hex(s: str) -> int:
    return int(str(s), 16)


@dataclass
class RC4ReplayResult:
    out: bytes
    state: bytes


def advapi_rc4_xor_replay(state_blob_0x120: bytes, input_bytes: bytes, n: int) -> RC4ReplayResult:
    """
    Replay ADVAPI32!rc4 as observed at 77dd8633.

    Captured state pointer passed to ADVAPI32!rc4 points to state+0x1c.
    Layout at that pointer:
        +0x000 .. +0x0ff : RC4 S-box
        +0x100          : RC4 i
        +0x101          : RC4 j
        +0x102 ..       : surrounding/tail bytes, left unchanged by PRGA

    ADVAPI32!rc4 XORs the keystream into the destination buffer in-place.
    Therefore:
        out_after = out_before XOR RC4_keystream
    """
    if len(state_blob_0x120) < 0x102:
        raise ValueError(f"state_blob too short: got {len(state_blob_0x120)} bytes, need at least 0x102")
    if len(input_bytes) < n:
        raise ValueError(f"input buffer too short: got {len(input_bytes)} bytes, need {n}")

    blob = bytearray(state_blob_0x120)
    S = blob[:0x100]
    i = blob[0x100]
    j = blob[0x101]

    out = bytearray(input_bytes[:n])

    for pos in range(n):
        i = (i + 1) & 0xFF
        si = S[i]
        j = (j + si) & 0xFF
        sj = S[j]

        # RC4 swap
        S[i], S[j] = sj, si

        k = S[(si + sj) & 0xFF]
        out[pos] ^= k

    blob[:0x100] = S
    blob[0x100] = i
    blob[0x101] = j

    return RC4ReplayResult(out=bytes(out), state=bytes(blob))


def load_result_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, list):
        if not obj:
            raise ValueError("JSON list is empty")
        # summary.json may be a one-element list; result.json is normally a dict.
        obj = obj[0]
    if not isinstance(obj, dict):
        raise ValueError("Unsupported JSON top-level type")
    return obj


def check_seedbase(data: Dict[str, Any]) -> Tuple[bool, str]:
    seed = data.get("seedbase", {})
    a = hx(seed.get("seedbase_after_80"))
    b = hx(seed.get("lsa_seed_slot_80"))
    ok = bool(a and b and a == b and seed.get("lsa_matches_seedbase_after") is True)
    return ok, f"seedbase_after == LSA slot: {ok}"


def check_ioctl(data: Dict[str, Any]) -> Tuple[bool, str]:
    ioctl = data.get("ioctl", {})
    ksec = ioctl.get("ksec_after_rc4_2", {}) or {}
    kbuf = hx(ksec.get("kernel_buf_0x100"))
    matches = ioctl.get("matching_advapi_ioctl") or []
    exact = []
    for m in matches:
        if hx(m.get("buf_0x100")) == kbuf and len(kbuf) == 0x100:
            exact.append(m)

    ok = len(exact) == 1
    if ok:
        m = exact[0]
        return ok, f"KSecDD RC4_2 0x100 == ADVAPI IOCTL buffer: True ({m.get('label')} @ {m.get('addr')}, line {m.get('line')})"
    return ok, f"KSecDD RC4_2 0x100 == ADVAPI IOCTL buffer: False (exact matches={len(exact)})"


def select_sequence(data: Dict[str, Any]) -> List[Tuple[int, str, str, str]]:
    rr = data.get("advapi_roundrobin", {})
    rows = []
    for r in rr.get("select_returns", []):
        rows.append((
            int(r.get("index", 0)),
            str(r.get("manager", "")),
            str(r.get("index_selected", "")),
            str(r.get("selected_state", "")),
        ))
    return rows


def check_round_robin(data: Dict[str, Any]) -> Tuple[bool, str]:
    rows = select_sequence(data)
    if not rows:
        return False, "round-robin select sequence: missing"

    # Focus on the primary ADVAPI manager observed in the measured chain.
    primary = rows[0][1]
    primary_rows = [r for r in rows if r[1] == primary]
    idx = [u32_hex(r[2]) for r in primary_rows]

    # The expected sequence may start at any point. For v5 it starts at 1.
    ok = True
    for prev, cur in zip(idx, idx[1:]):
        if cur != ((prev + 1) & 7):
            ok = False
            break

    first = ",".join(str(x) for x in idx[:10])
    return ok, f"ADVAPI manager {primary} round-robin sequence modulo 8: {ok} (first={first})"


def pair_prga_entries_returns(data: Dict[str, Any]) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    rr = data.get("advapi_roundrobin", {})
    entries = rr.get("prga_entries", [])
    returns = rr.get("prga_returns", [])
    # The parser records matching indices; zip is safe for the v5 output, but check line order.
    for e, r in zip(entries, returns):
        yield e, r


def check_prga_replay(data: Dict[str, Any], verbose: bool = False) -> Tuple[bool, str, List[str]]:
    logs: List[str] = []
    total_nonzero = 0
    ok_out = 0
    ok_state = 0
    skipped_zero = 0

    for e, r in pair_prga_entries_returns(data):
        n = u32_hex(e.get("len", "0"))
        if n == 0:
            # No output is generated; state should remain unchanged.
            skipped_zero += 1
            state_ok = hx(e.get("state_before_0x120")) == hx(r.get("state_after_0x120"))
            if verbose:
                logs.append(f"PRGA#{e.get('index')} line {e.get('line')} len=0 skipped; state_unchanged={state_ok}")
            continue

        total_nonzero += 1
        before_state = hx(e.get("state_before_0x120"))
        before_out = hx(e.get("out_before_40"))[:n]
        expected_out20 = hx(r.get("out20"))[:n]
        expected_state = hx(r.get("state_after_0x120"))

        replay = advapi_rc4_xor_replay(before_state, before_out, n)

        out_match = replay.out == expected_out20
        state_match = replay.state == expected_state
        ok_out += int(out_match)
        ok_state += int(state_match)

        sf = r.get("matching_systemfunction036_return_after")
        sys_match = bool(sf and hx(sf.get("out20")) == replay.out)

        logs.append(
            f"PRGA#{e.get('index')} line {e.get('line')}->{r.get('line')} "
            f"state={e.get('rc4_state')} len=0x{n:x} out={e.get('out_addr')} "
            f"replay_out={out_match} replay_state={state_match} sysfunc_match={sys_match} "
            f"out20={replay.out.hex()}"
        )

    ok = (total_nonzero > 0 and ok_out == total_nonzero and ok_state == total_nonzero)
    summary = (
        f"ADVAPI RC4 PRGA replay: {ok} "
        f"(nonzero={total_nonzero}, out_ok={ok_out}, state_ok={ok_state}, zero_len_skipped={skipped_zero})"
    )
    return ok, summary, logs


def check_prga_to_systemfunction(data: Dict[str, Any]) -> Tuple[bool, str]:
    rr = data.get("advapi_roundrobin", {})
    matches = rr.get("prga_returns_matching_systemfunction036") or []
    ok = len(matches) >= 1 and all(m.get("out20_matches_next_systemfunction036_return") for m in matches)
    return ok, f"PRGA output20 -> SystemFunction036_RETURN: {ok} (matches={len(matches)})"


def check_sysfunc_to_fips_aux(data: Dict[str, Any]) -> Tuple[bool, str]:
    rsa = data.get("rsaenh", {})
    cand = rsa.get("candidate_fips_after_ksec_with_aux_match") or []
    if not cand:
        return False, "SystemFunction036_RETURN -> rsaenh aux20: False (no candidate)"
    c = cand[0]
    ok = bool(c.get("aux20_matches_previous_systemfunction036_return"))
    return ok, (
        f"SystemFunction036_RETURN -> rsaenh aux20: {ok} "
        f"(FIPS#{c.get('index')} line={c.get('line')} state20={c.get('state20')} aux20={c.get('aux20')})"
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Replay/verify seed2state v5 ADVAPI round-robin RC4 path offline.")
    ap.add_argument("result_json", type=Path, help="seed2state_v5_roundrobin_*.result.json")
    ap.add_argument("--verbose", "-v", action="store_true", help="print per-PRGA replay details")
    ap.add_argument("--dump-select", action="store_true", help="print rc4_safe_select sequence")
    args = ap.parse_args(argv)

    data = load_result_json(args.result_json)

    checks: List[Tuple[str, bool, str]] = []

    ok, msg = check_seedbase(data)
    checks.append(("seedbase", ok, msg))

    ok, msg = check_ioctl(data)
    checks.append(("ioctl", ok, msg))

    ok, msg = check_round_robin(data)
    checks.append(("roundrobin", ok, msg))

    ok, msg, prga_logs = check_prga_replay(data, verbose=args.verbose)
    checks.append(("prga_replay", ok, msg))

    ok, msg = check_prga_to_systemfunction(data)
    checks.append(("prga_to_sysfunc", ok, msg))

    ok, msg = check_sysfunc_to_fips_aux(data)
    checks.append(("sysfunc_to_aux20", ok, msg))

    print("[seed2state v5 offline replay]")
    print(f"file: {data.get('file', args.result_json.name)}")
    print()

    for name, ok, msg in checks:
        print(f"[{name}] {'OK' if ok else 'FAIL'} - {msg}")

    if args.dump_select:
        print("\n[rc4_safe_select sequence]")
        for idx, manager, sel, state in select_sequence(data):
            print(f"  #{idx:02d} manager={manager} index={sel} state={state}")

    if args.verbose:
        print("\n[PRGA replay details]")
        for line in prga_logs:
            print("  " + line)

    # Treat the offline PRGA replay and bridges as critical.
    critical = {name: ok for name, ok, _ in checks}
    required = ["seedbase", "ioctl", "roundrobin", "prga_replay", "prga_to_sysfunc", "sysfunc_to_aux20"]
    all_required_ok = all(critical.get(k, False) for k in required)

    print()
    if all_required_ok:
        print("[RESULT] PASS")
        print("Observed/replayed path:")
        print("  seedbase_after -> LSA slot")
        print("  KSecDD RC4_2 output -> ADVAPI IOCTL buffer 0x100")
        print("  ADVAPI manager[8] -> rc4_safe_select -> rc4 PRGA")
        print("  PRGA output20 -> SystemFunction036 output20 -> rsaenh aux20")
        print()
        print("Residual not reconstructed here:")
        print("  IOCTL buffer 0x100 -> ADVAPI rekey/KSA of the 8 RC4 states")
        return 0

    print("[RESULT] FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
