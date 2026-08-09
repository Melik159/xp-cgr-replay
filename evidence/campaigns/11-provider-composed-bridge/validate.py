#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from validation.campaign_runner import main
raise SystemExit(main(Path(__file__).resolve().parent.name))
