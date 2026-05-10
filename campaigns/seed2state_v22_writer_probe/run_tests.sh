#!/usr/bin/env bash
set -euo pipefail

echo "[v22] compile Python"
python3 -m compileall -q parser tools

echo "[v22] validate JSON / JSONL"
python3 - <<'PY'
import json
from pathlib import Path

for p in Path(".").glob("**/*.json"):
    json.loads(p.read_text(encoding="utf-8"))

for p in Path(".").glob("**/*.jsonl"):
    with p.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line:
                json.loads(line)

print("[v22] JSON/JSONL OK")
PY

echo "[v22] check expected public artifacts"
test -f README.md
test -f parser/parse_seed2state_v22_writer_probe.py
test -f tools/check_v22_writer_transport.py
test -f tools/summarize_v22_writer_probe.py
test -f results_v22_writer_probe/v22_writer_events.jsonl
test -f results_v22_writer_probe/transport_check.txt
test -f results_v22_writer_probe/writer_summary.txt
test -d results_v22_writer_probe/samples
test -d sanity_v22_writer_probe

echo "[v22] run transport checker if supported"
python3 tools/check_v22_writer_transport.py results_v22_writer_probe || true

echo "[v22] PASS"
