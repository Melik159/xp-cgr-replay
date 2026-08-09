#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from validation.runner import main

raise SystemExit(main(["--block", "03-kernel-transport"]))
