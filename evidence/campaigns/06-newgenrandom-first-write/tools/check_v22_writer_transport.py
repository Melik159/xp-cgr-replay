#!/usr/bin/env python3
import argparse
import json

AFTER = "V22_WRITER_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100"
PRE = "V22_WRITER_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100"

ADVAPI_NEW = "V22_WRITER_ADVAPI_IOCTL_OUTBUF_100"
ADVAPI_LEGACY = "V22_1_ADVAPI_IOCTL_OUTBUF_100"

def dump_sha(ev, name):
    d = ev.get("dumps", {}).get(name)
    return d.get("sha256") if d else None

def advapi_sha(ev):
    return dump_sha(ev, ADVAPI_NEW) or dump_sha(ev, ADVAPI_LEGACY)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    args = ap.parse_args()

    events = [json.loads(line) for line in open(args.jsonl, encoding="utf-8")]

    cycles = []
    cur = None

    for ev in events:
        m = ev["marker"]

        if m == "V22_WRITER_NEWGENEX_ENTRY_F7459951":
            if cur:
                cycles.append(cur)
            cur = {
                "entry": ev,
                "writer": None,
                "after": None,
                "pre": None,
                "advapi": None,
            }

        elif cur and m == "V22_WRITER_OUTBUF_FIRST_WRITE":
            cur["writer"] = ev

        elif cur and m == "V22_WRITER_NEWGENEX_AFTER_GATHER_F74599A6":
            cur["after"] = ev

        elif cur and m == "V22_WRITER_NEWGENEX_PRE_RETURN_F74599C8":
            cur["pre"] = ev

        elif cur and m in ("V22_WRITER_ADVAPI_IOCTL_AFTER_C2", "V22_1_ADVAPI_IOCTL_AFTER_C2"):
            cur["advapi"] = ev
            cycles.append(cur)
            cur = None

    if cur:
        cycles.append(cur)

    print("cycle entry writer after pre advapi writer_eip writer_symbol transport_match status")

    ok = 0

    for i, c in enumerate(cycles, 1):
        after = dump_sha(c.get("after") or {}, AFTER)
        pre = dump_sha(c.get("pre") or {}, PRE)
        adv = advapi_sha(c.get("advapi") or {})

        match = after == pre == adv and after is not None
        status = "PASS" if match else "FAIL"

        if match:
            ok += 1

        writer_ev = c.get("writer") or {}
        kv = writer_ev.get("kv", {})
        writer_eip = kv.get("eip", "-")
        writer_symbol = kv.get("symbol_hint", "-")

        print(
            f"{i:02d}",
            (c.get("entry") or {}).get("line", "-"),
            (c.get("writer") or {}).get("line", "-"),
            (c.get("after") or {}).get("line", "-"),
            (c.get("pre") or {}).get("line", "-"),
            (c.get("advapi") or {}).get("line", "-"),
            writer_eip,
            repr(writer_symbol),
            match,
            status,
        )

    print(f"PASS={ok}/{len(cycles)}")

if __name__ == "__main__":
    main()
