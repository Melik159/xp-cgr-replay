#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_seed2state_v5_roundrobin.py

Parser for seed2state_v5_roundrobin WinDbg/KD logs.

Goals:
  - parse marker timeline and counts;
  - close VLH -> LSA seed-slot copy;
  - parse KSecDD RC4 output buffer;
  - parse ADVAPI IOCTL post-call direct dump and multi-candidate dumps;
  - parse SystemFunction036 entry/return pairs;
  - parse rsaenh FIPS entries and correlate aux20 with SystemFunction036 returns;
  - parse ADVAPI32 RC4 round-robin select/safe/PRGA events.
  - write per-log .result.json, .info.txt and global summary.json.

Usage:
  python parse_seed2state_v5_roundrobin.py ../seed2state_v5_roundrobin_*.log --pretty
  python parse_seed2state_v5_roundrobin.py ../seed2state_v5_roundrobin_*.log --outdir results_v4 --pretty
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

MARKER_RE = re.compile(r"^\[([A-Za-z0-9_]+)\]\s*$")
HEX_BYTE_RE = re.compile(r"\b[0-9a-fA-F]{2}\b")
DUMP_BYTE_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{8})\s+(.+)$")
DWORD_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]{8})\s+((?:[0-9a-fA-F]{8}\s*){1,16})")
KV_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*|arg[0-9])\s*=\s*([0-9a-fA-F`]+|None|null)")

SYSTEM_RETURN_MARKERS = {"SYSTEMFUNCTION036_RETURN", "SYSTEMFUNCTION036_RET"}
ADVAPI_IOCTL_MAIN_MARKERS = {"ADVAPI_IOCTL_AFTER_C2", "ADVAPI_IOCTL_AFTER"}
ADVAPI_CAND_PREFIX = "ADVAPI_IOCTL_CANDIDATE_"


def clean_hex_word(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = str(s).strip().replace("`", "").lower()
    if s in {"", "none", "null"}:
        return None
    return s


def norm_hex_bytes(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = re.sub(r"[^0-9a-fA-F]", "", s).lower()
    if not s:
        return None
    if len(s) % 2:
        return None
    return s


def int_hex(s: Optional[str]) -> Optional[int]:
    s = clean_hex_word(s)
    if not s:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def parse_kv_from_text(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in KV_RE.findall(text):
        cv = clean_hex_word(v)
        if cv is not None:
            out[k] = cv
    return out


def strip_ascii_column(rest: str) -> str:
    """Keep the hex byte area from a WinDbg `db` line.

    Example:
      '01 02 ...-10  ................' -> '01 02 ... 10'
    """
    rest = rest.replace("-", " ")
    tokens = []
    for tok in rest.split():
        if re.fullmatch(r"[0-9a-fA-F]{2}", tok):
            tokens.append(tok.lower())
        else:
            break
    return "".join(tokens)


def parse_db_blocks(lines: List[str]) -> Dict[str, str]:
    """Return {address: concatenated hex bytes} for contiguous db-style dumps.

    A block starts on any line whose left column is an 8-hex address and whose
    following tokens are two-hex bytes. Multiple non-contiguous blocks with the
    same address are appended only if they appear with the same first address;
    this is useful for repeated short dumps but harmless for our comparisons.
    """
    blocks: Dict[str, str] = {}
    current_start: Optional[str] = None
    current_hex: List[str] = []
    last_addr: Optional[int] = None

    def flush() -> None:
        nonlocal current_start, current_hex, last_addr
        if current_start and current_hex:
            blocks[current_start] = blocks.get(current_start, "") + "".join(current_hex)
        current_start = None
        current_hex = []
        last_addr = None

    for line in lines:
        m = DUMP_BYTE_LINE_RE.match(line)
        if not m:
            flush()
            continue
        addr_s, rest = m.group(1).lower(), m.group(2)
        h = strip_ascii_column(rest)
        if not h:
            flush()
            continue
        addr_i = int(addr_s, 16)
        if current_start is None:
            current_start = addr_s
            current_hex = [h]
            last_addr = addr_i
        else:
            # Continue only when the dump is plausibly contiguous.
            expected_min = (last_addr or addr_i) + max(1, len(current_hex[-1]) // 2)
            if addr_i >= expected_min and addr_i <= expected_min + 0x10:
                current_hex.append(h)
                last_addr = addr_i
            else:
                flush()
                current_start = addr_s
                current_hex = [h]
                last_addr = addr_i
    flush()
    return blocks


def first_dump_at_or_after(blocks: Dict[str, str], addr: Optional[str], nbytes: int) -> Optional[str]:
    addr = clean_hex_word(addr)
    if not addr:
        return None
    h = blocks.get(addr.lower())
    if not h:
        return None
    need = nbytes * 2
    return h[:need] if len(h) >= need else h


def first_dump_any(blocks: Dict[str, str], nbytes: int) -> Tuple[Optional[str], Optional[str]]:
    for addr, h in blocks.items():
        if h:
            return addr, h[: nbytes * 2]
    return None, None


def find_dump_containing(blocks: Dict[str, str], needle: Optional[str], min_prefix_bytes: int = 20) -> Optional[Dict[str, Any]]:
    needle = norm_hex_bytes(needle)
    if not needle:
        return None
    min_n = min(len(needle), min_prefix_bytes * 2)
    prefix = needle[:min_n]
    for addr, h in blocks.items():
        hh = norm_hex_bytes(h) or ""
        if not hh:
            continue
        if hh == needle:
            return {"addr": addr, "match_type": "exact", "matched_len": len(needle) // 2, "buf_0x100": hh[:0x100 * 2]}
        if needle in hh:
            return {"addr": addr, "match_type": "contains_full", "matched_len": len(needle) // 2, "buf_0x100": hh[:0x100 * 2]}
        if hh in needle and len(hh) >= min_n:
            return {"addr": addr, "match_type": "contained_in_ksec", "matched_len": len(hh) // 2, "buf_0x100": hh[:0x100 * 2]}
        if prefix and prefix in hh:
            return {"addr": addr, "match_type": "contains_prefix", "matched_len": len(prefix) // 2, "buf_0x100": hh[:0x100 * 2]}
    return None


def split_events(lines: List[str]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    for i, line in enumerate(lines, start=1):
        m = MARKER_RE.match(line.rstrip("\n"))
        if m:
            if cur is not None:
                cur["end_line"] = i - 1
                cur["text"] = "".join(cur["lines"])
                cur["kv"] = parse_kv_from_text(cur["text"])
                cur["db_blocks"] = parse_db_blocks(cur["lines"])
                events.append(cur)
            cur = {"marker": m.group(1), "line": i, "lines": [line]}
        elif cur is not None:
            cur["lines"].append(line)
    if cur is not None:
        cur["end_line"] = len(lines)
        cur["text"] = "".join(cur["lines"])
        cur["kv"] = parse_kv_from_text(cur["text"])
        cur["db_blocks"] = parse_db_blocks(cur["lines"])
        events.append(cur)
    return events


def marker_counts(events: List[Dict[str, Any]]) -> Dict[str, int]:
    return dict(Counter(ev["marker"] for ev in events))


def timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"n": i + 1, "line": ev["line"], "marker": ev["marker"]} for i, ev in enumerate(events)]


def first_event(events: List[Dict[str, Any]], marker: str) -> Optional[Dict[str, Any]]:
    for ev in events:
        if ev["marker"] == marker:
            return ev
    return None


def all_events(events: List[Dict[str, Any]], marker: str) -> List[Dict[str, Any]]:
    return [ev for ev in events if ev["marker"] == marker]


def parse_seedbase(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    vlh_entry = first_event(events, "VLH_ENTRY")
    if vlh_entry:
        kv = vlh_entry["kv"]
        seedbase = kv.get("SeedBase") or kv.get("seedbase")
        pool = kv.get("Pool") or kv.get("pool")
        plen = kv.get("Len") or kv.get("pool_len")
        out.update({
            "vlh_entry_line": vlh_entry["line"],
            "seedbase_addr": seedbase,
            "pool_addr": pool,
            "pool_len": plen,
            "seedbase_before_80": first_dump_at_or_after(vlh_entry["db_blocks"], seedbase, 0x50),
        })

    vlh_exit = first_event(events, "VLH_EXIT_SEED_AFTER")
    if vlh_exit:
        kv = vlh_exit["kv"]
        seedbase = kv.get("SeedBase") or out.get("seedbase_addr")
        out.update({
            "vlh_exit_line": vlh_exit["line"],
            "seedbase_after_80": first_dump_at_or_after(vlh_exit["db_blocks"], seedbase, 0x50),
        })

    lsa_after = first_event(events, "COPY_SEED_AFTER_TO_LSA_AFTER")
    if lsa_after:
        kv = lsa_after["kv"]
        lsa = kv.get("LsaSeedSlot") or kv.get("lsa_seed_slot")
        lsa80 = first_dump_at_or_after(lsa_after["db_blocks"], lsa, 0x50)
        out.update({
            "lsa_after_line": lsa_after["line"],
            "lsa_seed_slot": lsa,
            "lsa_seed_slot_80": lsa80,
            "lsa_matches_seedbase_after": bool(lsa80 and out.get("seedbase_after_80") and lsa80 == out.get("seedbase_after_80")),
        })
    else:
        out["lsa_matches_seedbase_after"] = False

    return out


def parse_ioctl(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    ksec = first_event(events, "KSEC_AFTER_RC4_2_OUTPUT")
    ksec_hex = None
    if ksec:
        kv = ksec["kv"]
        kbuf = kv.get("kernel_buf") or kv.get("kernel_buf_addr") or kv.get("buf")
        ksec_hex = first_dump_at_or_after(ksec["db_blocks"], kbuf, 0x100)
        out["ksec_after_rc4_2"] = {
            "line": ksec["line"],
            "kernel_buf_addr": kbuf,
            "kernel_buf_0x100": ksec_hex,
        }
    else:
        out["ksec_after_rc4_2"] = None

    # Direct ADVAPI post-IOCTL events, old/v3 format.
    direct: List[Dict[str, Any]] = []
    for ev in events:
        if ev["marker"] in ADVAPI_IOCTL_MAIN_MARKERS:
            kv = ev["kv"]
            addr = kv.get("addr") or kv.get("buf") or kv.get("out")
            # Prefer explicit addr dump; otherwise first db block.
            buf = first_dump_at_or_after(ev["db_blocks"], addr, 0x100)
            if not buf:
                addr2, buf2 = first_dump_any(ev["db_blocks"], 0x100)
                addr, buf = addr or addr2, buf2
            direct.append({
                "line": ev["line"],
                "addr": addr,
                "buf_0x100": buf,
                "matches_ksec_after_rc4_2": bool(ksec_hex and buf == ksec_hex),
            })

    # Multi-candidate events emitted by v4 02_advapi_ioctl_after_c2.txt.
    candidates: List[Dict[str, Any]] = []
    for ev in events:
        if ev["marker"].startswith(ADVAPI_CAND_PREFIX):
            kv = ev["kv"]
            label = ev["marker"][len(ADVAPI_CAND_PREFIX):]
            addr = kv.get("addr") or kv.get("buf")
            buf = first_dump_at_or_after(ev["db_blocks"], addr, 0x100)
            if not buf:
                addr2, buf2 = first_dump_any(ev["db_blocks"], 0x100)
                addr, buf = addr or addr2, buf2
            candidates.append({
                "line": ev["line"],
                "label": label,
                "addr": addr,
                "buf_0x100": buf,
                "matches_ksec_after_rc4_2": bool(ksec_hex and buf == ksec_hex),
            })

    all_adv = direct + candidates
    matches = [x for x in all_adv if x.get("matches_ksec_after_rc4_2")]

    # If exact equality failed, report prefix/contains matches for diagnosis.
    fuzzy: List[Dict[str, Any]] = []
    if ksec_hex:
        for ev in events:
            if ev["marker"] in ADVAPI_IOCTL_MAIN_MARKERS or ev["marker"].startswith(ADVAPI_CAND_PREFIX):
                m = find_dump_containing(ev["db_blocks"], ksec_hex)
                if m:
                    m.update({"line": ev["line"], "marker": ev["marker"]})
                    fuzzy.append(m)

    out.update({
        "advapi_ioctl_after_c2": direct,
        "advapi_ioctl_candidates": candidates,
        "advapi_ioctl_after_c2_count": len(direct),
        "advapi_ioctl_candidate_count": len(candidates),
        "matching_advapi_ioctl": matches,
        "matching_advapi_ioctl_count": len(matches),
        "fuzzy_matching_advapi_ioctl": fuzzy,
        "fuzzy_matching_advapi_ioctl_count": len(fuzzy),
    })
    return out


def parse_systemfunction036(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    returns: List[Dict[str, Any]] = []

    for ev in events:
        if ev["marker"] == "SYSTEMFUNCTION036_ENTRY":
            kv = ev["kv"]
            buf = kv.get("buf") or kv.get("buf_addr") or kv.get("arg1")
            length = kv.get("len") or kv.get("arg2")
            ret = kv.get("ret")
            pre20 = first_dump_at_or_after(ev["db_blocks"], buf, 0x14)
            entries.append({
                "index": len(entries) + 1,
                "line": ev["line"],
                "ret": ret,
                "buf_addr": buf,
                "len": length,
                "buf20_before": pre20,
            })
        elif ev["marker"] in SYSTEM_RETURN_MARKERS:
            kv = ev["kv"]
            out_addr = kv.get("out_addr") or kv.get("buf") or kv.get("buf_addr") or kv.get("addr") or kv.get("out")
            length = kv.get("len")
            out20 = first_dump_at_or_after(ev["db_blocks"], out_addr, 0x14)
            if not out20:
                addr2, out20b = first_dump_any(ev["db_blocks"], 0x14)
                out_addr, out20 = out_addr or addr2, out20b
            returns.append({
                "index": len(returns) + 1,
                "line": ev["line"],
                "out_addr": out_addr,
                "len": length,
                "out20": out20,
            })

    # Pair entries and returns by temporal order when possible.
    paired: List[Dict[str, Any]] = []
    ri = 0
    for e in entries:
        rmatch = None
        while ri < len(returns):
            if returns[ri]["line"] > e["line"]:
                rmatch = returns[ri]
                ri += 1
                break
            ri += 1
        p = dict(e)
        p["return"] = rmatch
        if rmatch:
            p["entry_buf_matches_return_addr"] = bool(e.get("buf_addr") and rmatch.get("out_addr") and e["buf_addr"] == rmatch["out_addr"])
        else:
            p["entry_buf_matches_return_addr"] = False
        paired.append(p)

    return {
        "entry_count": len(entries),
        "return_count": len(returns),
        "entries": entries,
        "returns": returns,
        "paired_by_time": paired,
    }


def nearest_prior(items: List[Dict[str, Any]], line: int) -> Optional[Dict[str, Any]]:
    prior = [x for x in items if x.get("line", -1) < line]
    return prior[-1] if prior else None


def find_matching_sysret(sysrets: List[Dict[str, Any]], aux20: Optional[str], line: int) -> Optional[Dict[str, Any]]:
    if not aux20:
        return None
    prior = [r for r in sysrets if r.get("line", -1) < line and r.get("out20") == aux20]
    return prior[-1] if prior else None



def find_matching_sysret_after(sysrets: List[Dict[str, Any]], out20: Optional[str], line: int) -> Optional[Dict[str, Any]]:
    if not out20:
        return None
    later = [r for r in sysrets if r.get("line", -1) > line and r.get("out20") == out20]
    return later[0] if later else None


def parse_advapi_roundrobin(events: List[Dict[str, Any]], system036: Dict[str, Any]) -> Dict[str, Any]:
    selects_entry: List[Dict[str, Any]] = []
    selects_return: List[Dict[str, Any]] = []
    safe_entries: List[Dict[str, Any]] = []
    prga_entries: List[Dict[str, Any]] = []
    prga_returns: List[Dict[str, Any]] = []
    sysrets = system036.get("returns", [])

    for ev in events:
        kv = ev["kv"]
        blocks = ev["db_blocks"]
        m = ev["marker"]

        if m == "ADVAPI_RC4_SELECT_ENTRY":
            manager = kv.get("manager")
            selects_entry.append({
                "index": len(selects_entry) + 1,
                "line": ev["line"],
                "manager": manager,
                "index_out": kv.get("index_out"),
                "value_out": kv.get("value_out"),
                "global_counter": kv.get("global_counter"),
                "manager_head": first_dump_at_or_after(blocks, manager, 0x80),
            })

        elif m == "ADVAPI_RC4_SELECT_RETURN":
            manager = kv.get("manager")
            selected_state = kv.get("selected_state")
            index_hex = kv.get("index")
            # Try to recover selected state from manager table if not printed.
            if not selected_state and manager and index_hex:
                # not possible from parsed dump alone unless table dwords are parsed; leave None.
                pass
            selects_return.append({
                "index": len(selects_return) + 1,
                "line": ev["line"],
                "manager": manager,
                "index_selected": index_hex,
                "value": kv.get("value"),
                "selected_state": selected_state,
                "global_counter": kv.get("global_counter"),
                "manager_head": first_dump_at_or_after(blocks, manager, 0x80),
                "selected_state_head": first_dump_at_or_after(blocks, selected_state, 0x80),
                "selected_state_sbox": first_dump_at_or_after(blocks, clean_hex_word(hex((int(selected_state,16)+0x1c) if selected_state else 0))[2:] if selected_state else None, 0x100) if selected_state else None,
            })

        elif m == "ADVAPI_RC4_SAFE_ENTRY":
            manager = kv.get("manager")
            out_addr = kv.get("out")
            safe_entries.append({
                "index": len(safe_entries) + 1,
                "line": ev["line"],
                "manager": manager,
                "index_or_mask": kv.get("index_or_mask"),
                "len": kv.get("len"),
                "out_addr": out_addr,
                "manager_head": first_dump_at_or_after(blocks, manager, 0x80),
                "out_before_40": first_dump_at_or_after(blocks, out_addr, 0x40),
            })

        elif m == "ADVAPI_RC4_PRGA_ENTRY":
            state = kv.get("rc4_state")
            out_addr = kv.get("out")
            prga_entries.append({
                "index": len(prga_entries) + 1,
                "line": ev["line"],
                "rc4_state": state,
                "len": kv.get("len"),
                "out_addr": out_addr,
                "state_before_0x120": first_dump_at_or_after(blocks, state, 0x120),
                "out_before_40": first_dump_at_or_after(blocks, out_addr, 0x40),
            })

        elif m == "ADVAPI_RC4_PRGA_RETURN":
            state = kv.get("rc4_state")
            out_addr = kv.get("out")
            out20 = first_dump_at_or_after(blocks, out_addr, 0x14)
            match_after = find_matching_sysret_after(sysrets, out20, ev["line"])
            prga_returns.append({
                "index": len(prga_returns) + 1,
                "line": ev["line"],
                "rc4_state": state,
                "len": kv.get("len"),
                "out_addr": out_addr,
                "state_after_0x120": first_dump_at_or_after(blocks, state, 0x120),
                "out_after_40": first_dump_at_or_after(blocks, out_addr, 0x40),
                "out20": out20,
                "matching_systemfunction036_return_after": match_after,
                "out20_matches_next_systemfunction036_return": bool(match_after),
            })

    matches = [x for x in prga_returns if x.get("out20_matches_next_systemfunction036_return")]
    return {
        "select_entry_count": len(selects_entry),
        "select_return_count": len(selects_return),
        "safe_entry_count": len(safe_entries),
        "prga_entry_count": len(prga_entries),
        "prga_return_count": len(prga_returns),
        "prga_return_matches_systemfunction036_count": len(matches),
        "select_entries": selects_entry,
        "select_returns": selects_return,
        "safe_entries": safe_entries,
        "prga_entries": prga_entries,
        "prga_returns": prga_returns,
        "prga_returns_matching_systemfunction036": matches,
    }


def parse_final_copies(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    copies: List[Dict[str, Any]] = []
    for ev in events:
        if ev["marker"] != "RSAENH_FINAL_COPY_6800D605":
            continue
        kv = ev["kv"]
        src = kv.get("src") or kv.get("src_addr") or kv.get("esi")
        dst = kv.get("dst") or kv.get("dst_addr") or kv.get("edi")
        length = kv.get("len_or_ecx") or kv.get("ecx") or kv.get("len")
        src32 = first_dump_at_or_after(ev["db_blocks"], src, 0x20)
        dst32 = first_dump_at_or_after(ev["db_blocks"], dst, 0x20)
        copies.append({
            "index": len(copies) + 1,
            "line": ev["line"],
            "src_addr": src,
            "dst_addr": dst,
            "len_or_ecx": length,
            "src32": src32,
            "dst32": dst32,
            "src32_matches_dst32": bool(src32 and dst32 and src32 == dst32),
        })
    return copies


def parse_rsaenh(events: List[Dict[str, Any]], system036: Dict[str, Any], seedbase: Dict[str, Any], ioctl: Dict[str, Any]) -> Dict[str, Any]:
    fips: List[Dict[str, Any]] = []
    sysrets = system036.get("returns", [])
    final_copies = parse_final_copies(events)
    vlh_exit_line = seedbase.get("vlh_exit_line")
    ksec_line = None
    if ioctl.get("ksec_after_rc4_2"):
        ksec_line = ioctl["ksec_after_rc4_2"].get("line")

    for ev in events:
        if ev["marker"] != "RSAENH_FIPS_ENTRY":
            continue
        kv = ev["kv"]
        arg1 = kv.get("arg1") or kv.get("arg1_state_addr")
        arg2 = kv.get("arg2") or kv.get("arg2_aux_addr")
        arg3 = kv.get("arg3") or kv.get("arg3_out_addr")
        arg4 = kv.get("arg4") or kv.get("arg4_len")
        gst = kv.get("global_state20") or kv.get("global_state20_addr") or "68031958"
        state20 = first_dump_at_or_after(ev["db_blocks"], arg1, 0x14)
        global_state20_current = first_dump_at_or_after(ev["db_blocks"], gst, 0x14)
        aux20 = first_dump_at_or_after(ev["db_blocks"], arg2, 0x14)
        arg3_pre_40 = first_dump_at_or_after(ev["db_blocks"], arg3, 0x28)

        nearest = nearest_prior(sysrets, ev["line"])
        matching = find_matching_sysret(sysrets, aux20, ev["line"])
        after_vlh = bool(vlh_exit_line and ev["line"] > vlh_exit_line)
        after_ksec = bool(ksec_line and ev["line"] > ksec_line)

        fc_after = None
        for fc in final_copies:
            if fc["line"] > ev["line"]:
                fc_after = fc
                break

        entry = {
            "index": len(fips) + 1,
            "line": ev["line"],
            "arg1_state_addr": arg1,
            "arg2_aux_addr": arg2,
            "arg3_out_addr": arg3,
            "arg4_len": arg4,
            "global_state20_addr": gst,
            "state20": state20,
            "global_state20_current": global_state20_current,
            "state20_matches_global": bool(state20 and global_state20_current and state20 == global_state20_current),
            "aux20": aux20,
            "arg3_pre_40": arg3_pre_40,
            "after_vlh_exit": after_vlh,
            "after_ksec_rc4_2_output": after_ksec,
            "nearest_systemfunction036_return_before": nearest,
            "matching_systemfunction036_return": matching,
            "aux20_matches_previous_systemfunction036_return": bool(matching),
            "final_copy_after": fc_after,
            "final_copy_src_equals_arg3": bool(fc_after and arg3 and fc_after.get("src_addr") == arg3),
        }
        fips.append(entry)

    candidate_after_vlh = [x for x in fips if x.get("after_vlh_exit") and x.get("aux20_matches_previous_systemfunction036_return")]
    candidate_after_ksec = [x for x in fips if x.get("after_ksec_rc4_2_output") and x.get("aux20_matches_previous_systemfunction036_return")]

    return {
        "algorithmcheck_count": len(all_events(events, "RSAENH_ALGORITHMCHECK")),
        "state_copy_6800d677_count": len(all_events(events, "RSAENH_STATE_COPY_6800D677")),
        "fips_entry_count": len(fips),
        "final_copy_6800d605_count": len(final_copies),
        "fips_entries": fips,
        "final_copies": final_copies,
        "candidate_fips_after_vlh_with_aux_match_count": len(candidate_after_vlh),
        "candidate_fips_after_ksec_with_aux_match_count": len(candidate_after_ksec),
        "candidate_fips_after_ksec_with_aux_match": candidate_after_ksec,
    }


def build_diagnostics(result: Dict[str, Any]) -> List[str]:
    d: List[str] = []
    seed = result.get("seedbase", {})
    ioctl = result.get("ioctl", {})
    sysf = result.get("systemfunction036", {})
    rsa = result.get("rsaenh", {})
    rr = result.get("advapi_roundrobin", {})

    if not seed.get("lsa_matches_seedbase_after"):
        d.append("LSA seed slot does not match seedbase_after, or one of the dumps is missing.")
    if not ioctl.get("matching_advapi_ioctl_count"):
        if ioctl.get("advapi_ioctl_candidate_count"):
            d.append("No ADVAPI IOCTL candidate buffer matched KSEC_AFTER_RC4_2_OUTPUT exactly.")
        else:
            d.append("No ADVAPI IOCTL candidate dumps were parsed; update 02_advapi_ioctl_after_c2.txt to emit ADVAPI_IOCTL_CANDIDATE_* markers.")
    if not ioctl.get("matching_advapi_ioctl_count") and ioctl.get("fuzzy_matching_advapi_ioctl_count"):
        d.append("A fuzzy/prefix ADVAPI IOCTL match exists; inspect fuzzy_matching_advapi_ioctl for offset or partial-copy behavior.")
    if sysf.get("entry_count") != sysf.get("return_count"):
        d.append("SYSTEMFUNCTION036_ENTRY count differs from SYSTEMFUNCTION036_RETURN count; pair by aux20 or return address, not by index only.")
    if not rsa.get("candidate_fips_after_ksec_with_aux_match_count"):
        d.append("No FIPS entry after KSEC output has aux20 matching a previous SystemFunction036 return.")
    if not rr.get("prga_return_count"):
        d.append("No ADVAPI RC4 PRGA return events parsed; add rc4 breakpoints or verify symbols ADVAPI32!rc4_safe_select/rc4_safe/rc4.")
    elif not rr.get("prga_return_matches_systemfunction036_count"):
        d.append("ADVAPI RC4 PRGA outputs were parsed, but none matched a subsequent SystemFunction036 return20.")
    return d


def parse_one(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    events = split_events(lines)
    seed = parse_seedbase(events)
    ioctl = parse_ioctl(events)
    sysf = parse_systemfunction036(events)
    rr = parse_advapi_roundrobin(events, sysf)
    rsa = parse_rsaenh(events, sysf, seed, ioctl)

    result: Dict[str, Any] = {
        "file": path,
        "event_count": len(events),
        "marker_counts": marker_counts(events),
        "timeline": timeline(events),
        "seedbase": seed,
        "ioctl": ioctl,
        "systemfunction036": sysf,
        "advapi_roundrobin": rr,
        "rsaenh": rsa,
    }
    result["diagnostics"] = build_diagnostics(result)
    return result


def write_info(result: Dict[str, Any], path: Path) -> None:
    seed = result.get("seedbase", {})
    ioctl = result.get("ioctl", {})
    sysf = result.get("systemfunction036", {})
    rsa = result.get("rsaenh", {})
    rr = result.get("advapi_roundrobin", {})
    lines: List[str] = []
    lines.append("[SEED2STATE V4 INFO]")
    lines.append(f"file={result.get('file')}")
    lines.append(f"events={result.get('event_count')}")
    lines.append("")

    lines.append("[MARKERS]")
    for k in sorted(result.get("marker_counts", {})):
        lines.append(f"{k:<36} {result['marker_counts'][k]}")
    lines.append("")

    lines.append("[SEEDBASE]")
    for k in ["vlh_entry_line", "vlh_exit_line", "seedbase_addr", "pool_addr", "pool_len", "lsa_seed_slot", "lsa_matches_seedbase_after"]:
        lines.append(f"{k:<32}: {seed.get(k)}")
    lines.append("")

    ksec = ioctl.get("ksec_after_rc4_2") or {}
    lines.append("[IOCTL]")
    lines.append(f"ksec_after_rc4_2_line       : {ksec.get('line')}")
    lines.append(f"kernel_buf_addr             : {ksec.get('kernel_buf_addr')}")
    lines.append(f"advapi_ioctl_after_c2_count : {ioctl.get('advapi_ioctl_after_c2_count')}")
    lines.append(f"advapi_ioctl_candidate_count: {ioctl.get('advapi_ioctl_candidate_count')}")
    lines.append(f"matching_ioctl_count        : {ioctl.get('matching_advapi_ioctl_count')}")
    lines.append(f"fuzzy_matching_ioctl_count  : {ioctl.get('fuzzy_matching_advapi_ioctl_count')}")
    if ioctl.get("matching_advapi_ioctl"):
        lines.append("matching_ioctl:")
        for m in ioctl["matching_advapi_ioctl"]:
            lines.append(f"  - line={m.get('line')} label={m.get('label')} addr={m.get('addr')}")
    if ioctl.get("fuzzy_matching_advapi_ioctl"):
        lines.append("fuzzy_ioctl:")
        for m in ioctl["fuzzy_matching_advapi_ioctl"]:
            lines.append(f"  - line={m.get('line')} marker={m.get('marker')} addr={m.get('addr')} type={m.get('match_type')} matched_len={m.get('matched_len')}")
    lines.append("")

    lines.append("[SYSTEMFUNCTION036]")
    lines.append(f"entry_count                 : {sysf.get('entry_count')}")
    lines.append(f"return_count                : {sysf.get('return_count')}")
    if sysf.get("paired_by_time"):
        p = sysf["paired_by_time"][:5]
        lines.append("first_pairs:")
        for e in p:
            r = e.get("return") or {}
            lines.append(f"  - entry#{e.get('index')} line={e.get('line')} buf={e.get('buf_addr')} len={e.get('len')} -> ret_line={r.get('line')} out={r.get('out_addr')} match_addr={e.get('entry_buf_matches_return_addr')}")
    lines.append("")

    lines.append("[ADVAPI RC4 ROUND-ROBIN]")
    lines.append(f"select_entry_count         : {rr.get('select_entry_count')}")
    lines.append(f"select_return_count        : {rr.get('select_return_count')}")
    lines.append(f"safe_entry_count           : {rr.get('safe_entry_count')}")
    lines.append(f"prga_entry_count           : {rr.get('prga_entry_count')}")
    lines.append(f"prga_return_count          : {rr.get('prga_return_count')}")
    lines.append(f"prga_matches_sysfunc_count : {rr.get('prga_return_matches_systemfunction036_count')}")
    if rr.get("select_returns"):
        lines.append("select_returns_first:")
        for x in rr["select_returns"][:5]:
            lines.append(f"  - line={x.get('line')} manager={x.get('manager')} index={x.get('index_selected')} state={x.get('selected_state')}")
    if rr.get("prga_returns_matching_systemfunction036"):
        lines.append("prga_to_systemfunction_matches:")
        for x in rr["prga_returns_matching_systemfunction036"][:5]:
            m = x.get("matching_systemfunction036_return_after") or {}
            lines.append(f"  - prga_line={x.get('line')} out={x.get('out_addr')} sysret_line={m.get('line')} out20={x.get('out20')}")
    lines.append("")

    lines.append("[RSAENH]")
    lines.append(f"algorithmcheck_count        : {rsa.get('algorithmcheck_count')}")
    lines.append(f"state_copy_6800d677_count   : {rsa.get('state_copy_6800d677_count')}")
    lines.append(f"fips_entry_count            : {rsa.get('fips_entry_count')}")
    lines.append(f"final_copy_6800d605_count   : {rsa.get('final_copy_6800d605_count')}")
    lines.append(f"candidate_after_vlh_aux     : {rsa.get('candidate_fips_after_vlh_with_aux_match_count')}")
    lines.append(f"candidate_after_ksec_aux    : {rsa.get('candidate_fips_after_ksec_with_aux_match_count')}")
    lines.append("")

    lines.append("[CANDIDATE FIPS CHAINS]")
    cands = rsa.get("candidate_fips_after_ksec_with_aux_match") or []
    if not cands:
        lines.append("None")
    for c in cands:
        mr = c.get("matching_systemfunction036_return") or {}
        fc = c.get("final_copy_after") or {}
        lines.append(
            f"FIPS#{c.get('index')} line={c.get('line')} "
            f"sysret_line={mr.get('line')} final_copy_line={fc.get('line')} "
            f"state20={c.get('state20')} aux20={c.get('aux20')}"
        )
    lines.append("")

    if result.get("diagnostics"):
        lines.append("[DIAGNOSTICS]")
        for x in result["diagnostics"]:
            lines.append(f"- {x}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def safe_stem(path: str) -> str:
    name = Path(path).name
    if name.lower().endswith(".log"):
        name = name[:-4]
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+", help="Log file(s) or glob(s)")
    ap.add_argument("--outdir", default="results", help="Output directory")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--stdout", action="store_true", help="Also print parsed result JSON to stdout")
    args = ap.parse_args()

    paths: List[str] = []
    for pat in args.logs:
        g = sorted(glob.glob(pat))
        paths.extend(g if g else [pat])
    paths = [p for p in paths if os.path.isfile(p)]
    if not paths:
        raise SystemExit("no input log files found")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    summary: List[Dict[str, Any]] = []
    for p in paths:
        result = parse_one(p)
        stem = safe_stem(p)
        json_path = outdir / f"{stem}.result.json"
        info_path = outdir / f"{stem}.info.txt"
        json_path.write_text(json.dumps(result, indent=2 if args.pretty else None, sort_keys=False), encoding="utf-8")
        write_info(result, info_path)

        summ = {
            "file": result.get("file"),
            "event_count": result.get("event_count"),
            "marker_counts": result.get("marker_counts"),
            "diagnostics": result.get("diagnostics"),
            "lsa_matches_seedbase_after": result.get("seedbase", {}).get("lsa_matches_seedbase_after"),
            "matching_ioctl_count": result.get("ioctl", {}).get("matching_advapi_ioctl_count"),
            "fuzzy_matching_ioctl_count": result.get("ioctl", {}).get("fuzzy_matching_advapi_ioctl_count"),
            "candidate_fips_after_ksec_aux": result.get("rsaenh", {}).get("candidate_fips_after_ksec_with_aux_match_count"),
            "systemfunction036_entry_count": result.get("systemfunction036", {}).get("entry_count"),
            "systemfunction036_return_count": result.get("systemfunction036", {}).get("return_count"),
            "roundrobin_prga_return_count": result.get("advapi_roundrobin", {}).get("prga_return_count"),
            "roundrobin_prga_matches_sysfunc": result.get("advapi_roundrobin", {}).get("prga_return_matches_systemfunction036_count"),
        }
        summary.append(summ)
        print(f"[OK] wrote {json_path}")
        print(f"[OK] wrote {info_path}")
        print(
            f"[INFO] file={p} events={result.get('event_count')} "
            f"ioctl_matches={summ['matching_ioctl_count']} "
            f"fuzzy_ioctl={summ['fuzzy_matching_ioctl_count']} "
            f"candidate_fips_after_ksec_aux={summ['candidate_fips_after_ksec_aux']} "
            f"diagnostics={len(result.get('diagnostics') or [])}"
        )
        if args.stdout:
            print(json.dumps(result, indent=2 if args.pretty else None))

    summary_path = outdir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2 if args.pretty else None), encoding="utf-8")
    print(f"[OK] wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
