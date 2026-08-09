#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

MARK_NEWGEN = "V24_CLOSEG_NEWGENEX_ENTRY_F7459951"


def split_events(text):
    events = []
    cur = None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\[([A-Za-z0-9_]+)\]$", line.strip())
        if m:
            cur = {"marker": m.group(1), "line": lineno, "text": []}
            events.append(cur)
        elif cur is not None:
            cur["text"].append(line)
    return events


def eval_hex(ev):
    if not ev:
        return None
    for line in ev.get("text", []):
        m = re.search(r"Evaluate expression:\s+-?\d+\s+=\s+([0-9a-fA-F]+)", line)
        if m:
            return int(m.group(1), 16)
    return None


def dump_bytes(ev):
    if not ev:
        return b""
    out = bytearray()
    for line in ev.get("text", []):
        # WinDbg db line, e.g.:
        # 8a0fcc50  23 ac ...-...  ascii
        if not re.match(r"^[0-9a-fA-F]{8}\s+", line):
            continue
        rest = line[9:].lstrip()
        # Split the byte columns from the ASCII rendering.
        byte_cols = re.split(r"\s{2,}", rest, maxsplit=1)[0]
        toks = re.findall(r"[0-9a-fA-F]{2}|\?\?", byte_cols)
        if not toks or any(t == "??" for t in toks):
            # Unreadable memory: do not treat it as a valid dump.
            continue
        out.extend(int(t, 16) for t in toks)
    return bytes(out)


def dd_bytes(ev):
    if not ev:
        return None, b""
    base = None
    out = bytearray()
    for line in ev.get("text", []):
        m = re.match(r"^([0-9a-fA-F]{8})\s+((?:[0-9a-fA-F]{8}\s*)+)$", line.strip())
        if not m:
            continue
        if base is None:
            base = int(m.group(1), 16)
        for dword in m.group(2).split():
            out.extend(int(dword, 16).to_bytes(4, "little"))
    return base, bytes(out)


def rc4_ksa(key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    return bytes(s) + b"\x00\x00"


def rc4_xor_from_state(state, data):
    s = list(state[:256])
    i = state[256] if len(state) > 256 else 0
    j = state[257] if len(state) > 257 else 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xff]
        out.append(b ^ k)
    return bytes(out), bytes(s) + bytes([i, j])


def group_cycles(events):
    cycles = []
    cur = None
    for ev in events:
        marker = ev["marker"]
        if marker == MARK_NEWGEN:
            if cur is not None:
                cycles.append(cur)
            cur = {"entry": ev, "rc4_keys": [], "rc4s": [], "by_marker": {marker: [ev]}}
            continue
        if cur is None:
            continue
        cur.setdefault("by_marker", {}).setdefault(marker, []).append(ev)

        if marker == "V24_CLOSEG_RC4_KEY_ENTRY_F745F15D":
            cur["rc4_keys"].append({"entry": ev})
        elif marker.startswith("V24_CLOSEG_RC4_KEY_") and cur["rc4_keys"]:
            cur["rc4_keys"][-1][marker] = ev
        elif marker == "V24_CLOSEG_RC4_ENTRY_F745F010":
            cur["rc4s"].append({"entry": ev})
        elif (marker.startswith("V24_CLOSEG_RC4_") or marker.startswith("V24_CLOSEG_FIRST_WRITE") or marker == "V24_CLOSEG_STACK_AT_FIRST_WRITE") and cur["rc4s"]:
            cur["rc4s"][-1][marker] = ev
    if cur is not None:
        cycles.append(cur)
    return cycles


def first(cycle, marker):
    return cycle.get("by_marker", {}).get(marker, [None])[0]


def validate(log_path):
    events = split_events(Path(log_path).read_text(errors="replace"))
    cycles = group_cycles(events)

    total_ksa = total_prga = 0
    pass_ksa = pass_prga = 0
    pass_after_pre = 0
    pass_advapi_prefix = 0

    print("cycle entry vlh rc4_key rc4_prga_xor after_pre advapi_frame_prefix status")

    for idx, cycle in enumerate(cycles, 1):
        vlh = 1 if first(cycle, "V24_CLOSEG_VLH_CHECKPOINT_F7459724") else 0

        ksa_ok_count = 0
        for n, key_ev in enumerate(cycle["rc4_keys"]):
            total_ksa += 1
            keylen = eval_hex(key_ev.get("V24_CLOSEG_RC4_KEY_ARG_KEYLEN_T9"))
            keybuf = dump_bytes(key_ev.get("V24_CLOSEG_RC4_KEY_KEYBUF_100"))
            rc4_ev = cycle["rc4s"][n] if n < len(cycle["rc4s"]) else None
            state_entry = dump_bytes(rc4_ev.get("V24_CLOSEG_RC4_STATE_ENTRY_120")) if rc4_ev else b""
            ok = bool(keylen and len(keybuf) >= keylen and len(state_entry) >= 258 and rc4_ksa(keybuf[:keylen])[:258] == state_entry[:258])
            if ok:
                ksa_ok_count += 1
                pass_ksa += 1

        prga_ok_count = 0
        for rc4_ev in cycle["rc4s"]:
            total_prga += 1
            n = eval_hex(rc4_ev.get("V24_CLOSEG_RC4_ARG_LEN_T5"))
            state_entry = dump_bytes(rc4_ev.get("V24_CLOSEG_RC4_STATE_ENTRY_120"))
            state_return = dump_bytes(rc4_ev.get("V24_CLOSEG_RC4_STATE_RETURN_120"))
            before = dump_bytes(rc4_ev.get("V24_CLOSEG_RC4_OUTBUF_BEFORE_100"))
            returned = dump_bytes(rc4_ev.get("V24_CLOSEG_RC4_OUTBUF_RETURN_100"))
            ok = False
            if n and len(state_entry) >= 258 and len(state_return) >= 258 and len(before) >= n and len(returned) >= n:
                replay, new_state = rc4_xor_from_state(state_entry, before[:n])
                ok = (replay == returned[:n] and new_state[:258] == state_return[:258])
            if ok:
                prga_ok_count += 1
                pass_prga += 1

        after = dump_bytes(first(cycle, "V24_CLOSEG_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100"))
        pre = dump_bytes(first(cycle, "V24_CLOSEG_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100"))
        after_pre = bool(len(after) >= 256 and len(pre) >= 256 and after[:256] == pre[:256])
        if after_pre:
            pass_after_pre += 1

        # In this V24 log, ADVAPI_IOCTL_OUTBUF_100 is unreadable (??). Fallback:
        # The output buffer starts at @esp+0x70 inside V24_CLOSEG_ADVAPI_IOCTL_FRAME_DWORDS.
        # The frame dump contains only 0x90 bytes of the 0x100-byte user outbuf, so this is a prefix check.
        base, frame = dd_bytes(first(cycle, "V24_CLOSEG_ADVAPI_IOCTL_FRAME_DWORDS"))
        prefix = frame[0x70:] if len(frame) > 0x70 else b""
        advapi_prefix = bool(len(after) >= len(prefix) > 0 and after[:len(prefix)] == prefix)
        if advapi_prefix:
            pass_advapi_prefix += 1

        status = "PASS_PARTIAL_ADVAPI" if (vlh and ksa_ok_count == len(cycle["rc4_keys"]) and prga_ok_count == len(cycle["rc4s"]) and after_pre and advapi_prefix) else "FAIL"
        print(f"{idx:02d} {cycle['entry']['line']} {vlh} {ksa_ok_count}/{len(cycle['rc4_keys'])} {prga_ok_count}/{len(cycle['rc4s'])} {after_pre} {advapi_prefix}:{len(prefix)}/256 {status}")

    print()
    print(f"V24_CLOSEG rc4_key_ksa PASS={pass_ksa}/{total_ksa}")
    print(f"V24_CLOSEG rc4_prga_xor PASS={pass_prga}/{total_prga}")
    print(f"V24_CLOSEG ksec_after_pre PASS={pass_after_pre}/{len(cycles)}")
    print(f"V24_CLOSEG advapi_frame_prefix PASS={pass_advapi_prefix}/{len(cycles)}")
    if pass_ksa == total_ksa and pass_prga == total_prga and pass_after_pre == len(cycles) and pass_advapi_prefix == len(cycles):
        print("OVERALL=PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX")
    else:
        print("OVERALL=INCOMPLETE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    args = ap.parse_args()
    validate(args.log)


if __name__ == "__main__":
    main()
