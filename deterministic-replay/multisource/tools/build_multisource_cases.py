#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

# Representative output-effective byte positions per source.
# 30 positions * 8 KSec events = 240 one-byte cases.
REPRESENTATIVE = {
    "allocator": (0, 7),
    "pid": (0, 7),
    "tid": (0, 7),
    "tick": (0, 15),
    "cpu": (0, 15),
    "qsi03": (0, 55),
    "qsi07": (0, 31),
    "qsi02": (0, 319),
    "qsi21": (0, 23),
    "qsi2d": (0, 39),
    "qsi05": (0, 20, 23, 3527),
    "qsi08": (0, 20, 23, 191),
    "qsi17": (20, 23),
}

TRANSFORM = {
    **{k: "copy" for k in ("allocator","pid","tid","tick","cpu","qsi03","qsi07","qsi02","qsi21","qsi2d")},
    "qsi05": "sha1_plus_suffix",
    "qsi08": "sha1_plus_suffix",
    "qsi17": "sha1_empty_plus_suffix",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package-root", type=Path, required=True)
    ap.add_argument("--run", default="run1")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--events", default="0,1,2,3,4,5,6,7")
    a = ap.parse_args()

    root = a.package_root.resolve()
    rd = root / "fixtures" / a.run
    src = json.loads((rd / "sources.json").read_text(encoding="utf-8"))
    # Self-contained fixture-shape validation; no dependency on package-root/tools.
    if not isinstance(src.get("ksec_events"), list) or len(src["ksec_events"]) != 8:
        raise SystemExit("sources.json: expected exactly 8 ksec_events")
    if src.get("requested_output_length") != 32:
        raise SystemExit("sources.json: requested_output_length must be 32")
    events = tuple(int(x) for x in a.events.split(",") if x.strip())

    rows = []
    for ev in events:
        if not 0 <= ev < len(src["ksec_events"]):
            raise SystemExit(f"bad event {ev}")
        rawmap = src["ksec_events"][ev]["sources"]
        for name, offsets in REPRESENTATIVE.items():
            raw = bytes.fromhex(rawmap[name])
            for off in offsets:
                if off >= len(raw):
                    raise SystemExit(f"{name}:{off} outside source size {len(raw)}")
                # Cross-check that this position is output-effective in model's pool.
                if name == "cpu" and off >= 16:
                    raise SystemExit("cpu representative outside copied 16-byte pool range")
                if name == "qsi17" and not 20 <= off < 24:
                    raise SystemExit("qsi17 representative outside effective suffix 20:24")
                rows.append({
                    "id": f"{a.run}_e{ev}_{name}_o{off}",
                    "run": a.run,
                    "event": ev,
                    "source": name,
                    "offset": off,
                    "transform": TRANSFORM[name],
                    "lo": 0,
                    "hi": 255,
                    "trials": 256,
                    "original_value": raw[off],
                    "source_size": len(raw),
                    "output_effect": "direct_or_transitive" if ev <= 1 else "none_expected_for_32B_output",
                })

    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"MULTISOURCE_CASES PASS run={a.run} events={len(events)} cases={len(rows)} trials={len(rows)*256} out={a.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
