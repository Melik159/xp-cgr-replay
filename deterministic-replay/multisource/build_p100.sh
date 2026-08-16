#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/cgr-cuda-multisource}"
nvcc -O3 -std=c++17 -arch=sm_60 -Wno-deprecated-gpu-targets \
  -Xptxas=-v \
  "$HERE/cuda/cgr_cuda_multisource.cu" \
  -o "$OUT"
echo "BUILD PASS out=$OUT"
