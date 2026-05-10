#!/usr/bin/env python3
import argparse
import json

NEWGEN_ENTRY = "V23_RC4_NEWGENEX_ENTRY_F7459951"
VLH = "V23_RC4_VLH_CHECKPOINT_F7459724"
RC4_ENTRY = "V23_RC4_ENTRY_F745F010"
RC4_FIRST_WRITE = "V23_RC4_OUTBUF_FIRST_WRITE"
RC4_RETURN = "V23_RC4_RETURN_F745F15A"
AFTER = "V23_RC4_NEWGENEX_AFTER_GATHER_F74599A6"
PRE = "V23_RC4_NEWGENEX_PRE_RETURN_F74599C8"
ADVAPI = "V23_RC4_ADVAPI_IOCTL_AFTER_C2"

D_AFTER = "V23_RC4_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100"
D_PRE = "V23_RC4_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100"
D_ADVAPI = "V23_RC4_ADVAPI_IOCTL_OUTBUF_100"

def dump_sha(ev, name):
    d = ev.get("dumps", {}).get(name)
    return d.get("sha256") if d else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    args = ap.parse_args()

    events = [json.loads(x) for x in open(args.jsonl, encoding="utf-8") if x.strip()]

    cycles = []
    cur = None

    for ev in events:
        m = ev["marker"]

        if m == NEWGEN_ENTRY:
            if cur:
                cycles.append(cur)
            cur = {
                "entry": ev,
                "vlh": [],
                "rc4_entry": [],
                "rc4_first_write": [],
                "rc4_return": [],
                "after": None,
                "pre": None,
                "advapi": None,
            }
            continue

        if cur is None:
            continue

        if m == VLH:
            cur["vlh"].append(ev)
        elif m == RC4_ENTRY:
            cur["rc4_entry"].append(ev)
        elif m == RC4_FIRST_WRITE:
            cur["rc4_first_write"].append(ev)
        elif m == RC4_RETURN:
            cur["rc4_return"].append(ev)
        elif m == AFTER:
            cur["after"] = ev
        elif m == PRE:
            cur["pre"] = ev
        elif m == ADVAPI:
            cur["advapi"] = ev

    if cur:
        cycles.append(cur)

    print("cycle entry vlh rc4_entry rc4_return first_write after pre advapi transport_match status")

    ok = 0

    for i, c in enumerate(cycles, 1):
        entry_line = c["entry"]["line"]
        vlh_n = len(c["vlh"])
        rc4_entry_n = len(c["rc4_entry"])
        rc4_return_n = len(c["rc4_return"])
        first_write_n = len(c["rc4_first_write"])

        after_line = c["after"]["line"] if c["after"] else "-"
        pre_line = c["pre"]["line"] if c["pre"] else "-"
        advapi_line = c["advapi"]["line"] if c["advapi"] else "-"

        sha_after = dump_sha(c["after"], D_AFTER) if c["after"] else None
        sha_pre = dump_sha(c["pre"], D_PRE) if c["pre"] else None
        sha_advapi = dump_sha(c["advapi"], D_ADVAPI) if c["advapi"] else None

        transport_match = bool(sha_after and sha_pre and sha_advapi and sha_after == sha_pre == sha_advapi)

        structural = (
            vlh_n == 1
            and rc4_entry_n == 2
            and rc4_return_n == 2
            and first_write_n == 1
            and c["after"] is not None
            and c["pre"] is not None
            and c["advapi"] is not None
        )

        status = "PASS" if structural and transport_match else "FAIL"
        if status == "PASS":
            ok += 1

        print(
            f"{i:02d} "
            f"{entry_line} "
            f"{vlh_n} "
            f"{rc4_entry_n} "
            f"{rc4_return_n} "
            f"{first_write_n} "
            f"{after_line} "
            f"{pre_line} "
            f"{advapi_line} "
            f"{transport_match} "
            f"{status}"
        )

    print(f"PASS={ok}/{len(cycles)}")

    if ok != len(cycles) or len(cycles) != 8:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
