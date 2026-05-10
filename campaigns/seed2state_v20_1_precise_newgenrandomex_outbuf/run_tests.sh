#!/usr/bin/env bash
set -euo pipefail

echo "[v20.1] compile"
python3 -m compileall -q .

echo "[v20.1] validate JSON/JSONL"
python3 - <<'PY'
import json, pathlib
for p in pathlib.Path(".").glob("**/*.json"):
    json.loads(p.read_text())
for p in pathlib.Path(".").glob("**/*.jsonl"):
    for i, line in enumerate(p.read_text().splitlines(), 1):
        if line.strip():
            json.loads(line)
print("[v20.1] structured files ok")
PY

# Remplace par la vraie commande de replay/parser :
# python3 parser/parse_seed2state_v20_1.py logs/sample.log --outdir results
# python3 parser/replay_seed2state_v20_1.py results/sample.result.json

echo "[v20.1] PASS"
