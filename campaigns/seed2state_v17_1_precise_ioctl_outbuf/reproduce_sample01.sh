#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

rm -rf sample01/samples
mkdir -p sample01/results sample01/samples

python3 parser/parse_seed2state_v17_1_precise.py \
  "sample01/raw/sample01.log" \
  --pretty \
  --jsonl "sample01/results/sample01.states.jsonl" \
  --samples "sample01/samples" \
  | tee "sample01/results/sample01.report.txt"

python3 tools/replay_prga_useful_only.py \
  sample01/samples

python3 tools/scan_ioctl_outbuf_to_rc4_ksa.py \
  sample01/samples \
  --csv "sample01/results/sample01.ksa_scan.csv" \
  | tee "sample01/results/sample01.ksa_scan.txt"

python3 tools/audit_sample01_negative_controls.py
