#!/usr/bin/env python3
import argparse, json, re, sys
from pathlib import Path

MARKERS = {
    "entry": "[V19C_CORE_ENTRY_6800D640]",
    "before_fips": "[V19C_BEFORE_FIPS_6800D6E7]",
    "fips_entry": "[V19C_FIPS_ENTRY_68027101]",
    "fips_return": "[V19C_FIPS_RETURN_6800D6FB]",
    "after_copy": "[V19C_AFTER_OUTPUT_COPY_6800D717]",
    "exit": "[V19C_CORE_EXIT_6800D737]",
}

HEXLINE = re.compile(r"^[0-9a-fA-F]{8}\s+((?:[0-9a-fA-F]{2}[ -]?){1,16})")
ARG_RE = re.compile(r"(retaddr|arg04|arg08|arg0c|arg10|arg14|arg18|arg1c|arg20|eax)=([0-9a-fA-F]+)")
PTR_RE = re.compile(r"(arg1_state20|arg2_aux20|arg3_out40)=([0-9a-fA-F]+)")

def parse_dump(lines, start, max_lines=4):
    out = []
    i = start
    while i < len(lines) and i < start + max_lines:
        m = HEXLINE.match(lines[i].strip())
        if not m:
            break
        part = m.group(1).replace("-", " ")
        out.extend(x.lower() for x in part.split() if len(x) == 2)
        i += 1
    return "".join(out), i

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--jsonl")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    lines = Path(args.log).read_text(errors="replace").splitlines()
    calls = []
    cur = None
    pending_dump = None

    for i, line in enumerate(lines):
        if MARKERS["entry"] in line:
            if cur:
                calls.append(cur)
            cur = {"index": len(calls)+1, "line_entry": i+1}
            pending_dump = None
            continue
        if cur is None:
            continue

        if "retaddr=" in line and "arg04=" in line:
            for k, v in ARG_RE.findall(line):
                cur[k] = v.lower()

        if "arg1_state20=" in line:
            for k, v in PTR_RE.findall(line):
                cur[k] = v.lower()

        # set expected next dump field
        if line.strip() == "[V19C_GLOBAL_68031958_CORE_ENTRY]":
            pending_dump = "state20_core_entry"
        elif line.strip() == "[V19C_ARG10_IF_ANY]":
            pending_dump = "arg10_bytes"
        elif line.strip() == "[V19C_STATE20_BEFORE_FIPS_68031958]":
            pending_dump = "state20_before_fips"
        elif line.strip() == "[V19C_AUX20_BEFORE_FIPS_EBP_M18]":
            pending_dump = "aux20_before_fips"
        elif line.strip() == "[V19C_OUT40_BEFORE_FIPS_EBP_M40]":
            pending_dump = "out40_before_fips"
        elif line.strip() == "[V19C_FIPS_ARG1_STATE20]":
            pending_dump = "fips_arg1_state20"
        elif line.strip() == "[V19C_FIPS_ARG2_AUX20]":
            pending_dump = "fips_arg2_aux20"
        elif line.strip() == "[V19C_FIPS_ARG3_OUT40_BEFORE]":
            pending_dump = "fips_arg3_out40_before"
        elif line.strip() == "[V19C_GLOBAL_68031958_AT_FIPS_ENTRY]":
            pending_dump = "state20_at_fips_entry"
        elif line.strip() == "[V19C_GLOBAL_68031958_AFTER_FIPS]":
            pending_dump = "state20_after_fips"
        elif line.strip() == "[V19C_AUX20_AFTER_FIPS_EBP_M18]":
            pending_dump = "aux20_after_fips"
        elif line.strip() == "[V19C_OUT40_AFTER_FIPS_EBP_M40]":
            pending_dump = "out40_after_fips"
        elif line.strip() == "[V19C_OUT40_AT_COPY_EBP_M40]":
            pending_dump = "out40_at_copy"
        elif line.strip() == "[V19C_USER_OUT_AFTER_COPY]":
            pending_dump = "user_out_after_copy"
        elif line.strip() == "[V19C_GLOBAL_68031958_AFTER_COPY]":
            pending_dump = "state20_after_copy"
        elif line.strip() == "[V19C_GLOBAL_68031958_CORE_EXIT]":
            pending_dump = "state20_core_exit"
        elif pending_dump and HEXLINE.match(line.strip()):
            hx, _ = parse_dump(lines, i)
            if hx:
                cur[pending_dump] = hx
            pending_dump = None

    if cur:
        calls.append(cur)

    # classify and recurrence
    for c in calls:
        c["complete"] = all(k in c for k in ("state20_before_fips","fips_arg2_aux20","out40_after_fips","state20_after_fips","state20_core_exit"))
        c["state20_before_eq_fips_arg1"] = (
            c.get("state20_before_fips","")[:40] == c.get("fips_arg1_state20","")[:40]
            if "fips_arg1_state20" in c else None
        )
        c["aux20_before_eq_fips_arg2"] = (
            c.get("aux20_before_fips","")[:40] == c.get("fips_arg2_aux20","")[:40]
            if "fips_arg2_aux20" in c else None
        )
        c["after_fips_eq_exit"] = (
            c.get("state20_after_fips","")[:40] == c.get("state20_core_exit","")[:40]
            if "state20_core_exit" in c else None
        )

    recurrence = []
    for a, b in zip(calls, calls[1:]):
        av = a.get("state20_core_exit") or a.get("state20_after_fips")
        bv = b.get("state20_core_entry")
        recurrence.append({
            "from": a["index"], "to": b["index"],
            "match": (av[:40] == bv[:40]) if av and bv else None,
            "after": av[:40] if av else None,
            "next_before": bv[:40] if bv else None,
        })

    if args.jsonl:
        with open(args.jsonl, "w") as f:
            for c in calls:
                f.write(json.dumps(c, sort_keys=True) + "\n")

    print("[SEED2STATE V19C FIPS STATE20 UPDATE REPORT]")
    print(f"file={args.log}")
    print(f"calls={len(calls)}")
    print(f"complete_calls={sum(1 for c in calls if c.get('complete'))}")
    print()
    for c in calls:
        print(f"#{c['index']} retaddr={c.get('retaddr')} arg10={c.get('arg10')} arg18={c.get('arg18')} complete={c.get('complete')}")
        print(f"  state20_before={c.get('state20_before_fips', c.get('state20_core_entry',''))[:40]}")
        print(f"  aux20         ={c.get('fips_arg2_aux20','')[:40]}")
        print(f"  out40_after   ={c.get('out40_after_fips','')[:80]}")
        print(f"  state20_after ={c.get('state20_after_fips', c.get('state20_core_exit',''))[:40]}")
        print(f"  aux_eq_arg2={c.get('aux20_before_eq_fips_arg2')} after_eq_exit={c.get('after_fips_eq_exit')}")
    print()
    print("[RECURRENCE]")
    for r in recurrence:
        print(f"call#{r['from']} -> call#{r['to']} match={r['match']}")
        print(f"  after     ={r['after']}")
        print(f"  next_entry={r['next_before']}")

if __name__ == "__main__":
    main()
