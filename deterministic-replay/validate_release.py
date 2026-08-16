#!/usr/bin/env python3

import subprocess
import sys

TESTS = [
    (
        ["python3", "tools/play_cgr.py", "--run", "run1"],
        "baseline_output=a37bf2d7c0c473fc92c62f5171adb25cabdb23a5bb9fcc6b3bd733aaeac53ad4",
        "historical Run1",
    ),
    (
        ["python3", "tools/play_cgr.py", "--run", "run2"],
        "baseline_output=73f3bee078d1335c3dda75994b505be400b1b29ecf2443000cf83128dfcd2fd8",
        "historical Run2",
    ),
    (
        [
            "python3",
            "tools/play_cgr.py",
            "--run",
            "run1",
            "--set",
            "ksec:0:qsi17:20=ff",
        ],
        "baseline_output=0a7eaa389b0365455c0b0c2ef0c99d1e7ed89eda8906e0f2bca2a3778b807b0c",
        "Run1 qsi17[20]=ff counterfactual",
    ),
]

failed = False

for command, expected, name in TESTS:
    proc = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    output = proc.stdout + proc.stderr

    if proc.returncode == 0 and expected in output:
        print(f"PASS {name}")
    else:
        print(f"FAIL {name}")
        print(output)
        failed = True

if failed:
    sys.exit(1)

print("OVERALL=PASS")
