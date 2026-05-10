#!/usr/bin/env bash
set -euo pipefail

echo "[v23] compile"
python3 -m compileall -q .

echo "[v23] find replay scripts"
find . -type f \( -name '*rc4*.py' -o -name '*replay*.py' \) -print

echo "[v23] validate structured files"
python3 - <<'PY'
import json, pathlib
for p in pathlib.Path(".").glob("**/*.json"):
    json.loads(p.read_text())
for p in pathlib.Path(".").glob("**/*.jsonl"):
    for i, line in enumerate(p.read_text().splitlines(), 1):
        if line.strip():
            json.loads(line)
print("[v23] json/jsonl ok")
PY

# Remplace par la vraie commande :
# python3 replay_seed2state_v23_rc4.py samples/sample.json --dump

echo "[v23] PASS"
