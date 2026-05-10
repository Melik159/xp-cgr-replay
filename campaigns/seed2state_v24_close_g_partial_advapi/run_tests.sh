#!/usr/bin/env bash
set -euo pipefail

echo "[v24] Python syntax check without pycache"
python3 - <<'PY'
from pathlib import Path

files = []
files += sorted(Path("parser").glob("*.py"))
files += sorted(Path("tools").glob("*.py"))

for p in files:
    src = p.read_text(encoding="utf-8")
    compile(src, str(p), "exec")

print("[v24] Python syntax OK")
PY

echo "[v24] validate JSON / JSONL"
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

print("[v24] JSON/JSONL OK")
PY

echo "[v24] check required public artifacts"
test -f README.md
test -f parser/parse_seed2state_v24_close_g.py
test -f tools/validate_v24_close_g.py
test -f tools/validate_v24_close_g_xor_from_log.py
test -f results_v24/v24_events.jsonl
test -f results_v24/transport_check.txt
test -f results_v24/transport_xor_from_log_check.txt
test -d results_v24/samples
test -d sanity_v24

echo "[v24] check expected partial verdict"
grep -q "OVERALL=PARTIAL_CLOSE_ADVAPI_DUMP_NEEDS_FIX" results_v24/transport_xor_from_log_check.txt
grep -q "rc4_key_ksa PASS=16/16" results_v24/transport_xor_from_log_check.txt
grep -q "rc4_prga_xor PASS=16/16" results_v24/transport_xor_from_log_check.txt
grep -q "ksec_after_pre PASS=8/8" results_v24/transport_xor_from_log_check.txt

if [[ -f SHA256SUMS ]]; then
  echo "[v24] verify SHA256SUMS"
  sha256sum -c SHA256SUMS
fi


echo "[v24] PASS"
