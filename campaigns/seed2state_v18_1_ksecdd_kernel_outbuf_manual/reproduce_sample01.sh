#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 scripts/check_ksec_kernel_to_advapi_ioctl.py \
  samples/sample01/raw \
  | tee reports/sample01.ksec_ioctl.txt

python3 scripts/check_ioctl_to_rc4_ksa.py \
  samples/sample01/raw \
  | tee reports/sample01.ioctl_ksa.txt

python3 scripts/replay_prga_useful_only.py \
  samples/sample01/raw \
  | tee reports/sample01.prga_replay.txt
