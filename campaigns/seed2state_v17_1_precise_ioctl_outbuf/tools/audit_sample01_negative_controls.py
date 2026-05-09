#!/usr/bin/env python3
from pathlib import Path
import hashlib
import sys

ROOT = Path("sample01/samples")

def sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return bytes(S)

def rc4_prga_xor(state_sij: bytes, data: bytes):
    if len(state_sij) < 258:
        raise ValueError("state_sij too short")
    S = bytearray(state_sij[:256])
    i = state_sij[256]
    j = state_sij[257]
    out = bytearray(data)

    for p in range(len(out)):
        i = (i + 1) & 0xff
        si = S[i]
        j = (j + si) & 0xff
        sj = S[j]
        S[i], S[j] = sj, si
        k = S[(si + sj) & 0xff]
        out[p] ^= k

    return bytes(out), bytes(S) + bytes([i, j])

def must(cond, msg):
    if not cond:
        print(f"[FAIL] {msg}")
        sys.exit(1)
    print(f"[OK] {msg}")

print("[AUDIT] sample01 anti-bullshit checks")

ioctls = sorted(ROOT.glob("ioctl_*/V17_1_IOCTL_OUTBUF_100.bin"))
prgas = sorted(ROOT.glob("prga_*"))

must(len(ioctls) == 8, f"8 IOCTL outbufs present, got {len(ioctls)}")
must(len(prgas) == 11, f"11 PRGA directories present, got {len(prgas)}")

outbufs = [p.read_bytes() for p in ioctls]
must(all(len(x) == 256 for x in outbufs), "all IOCTL outbufs are exactly 256 bytes")
must(len({sha1(x) for x in outbufs}) == 8, "all 8 IOCTL outbufs are distinct")

# Positive KSA checks: RC4 KSA(outbuf) must equal PRGA state_before_sij[:256]
# for the known direct mapping observed by the scan.
expected = {
    "prga_001": "ioctl_01",
    "prga_002": "ioctl_02",
    "prga_003": "ioctl_03",
    "prga_004": "ioctl_04",
    "prga_005": "ioctl_05",
    "prga_006": "ioctl_06",
    "prga_007": "ioctl_07",
    "prga_008": "ioctl_08",
    "prga_010": "ioctl_02",
    "prga_011": "ioctl_03",
}

for prga, ioctl in expected.items():
    key = (ROOT / ioctl / "V17_1_IOCTL_OUTBUF_100.bin").read_bytes()
    state = (ROOT / prga / "state_before_sij.bin").read_bytes()
    calc = rc4_ksa(key)
    must(calc == state[:256], f"KSA({ioctl}) == {prga}/state_before_sij[:256]")

    # Negative control: flip one byte in the key. The KSA state must no longer match.
    bad = bytearray(key)
    bad[0] ^= 1
    bad_calc = rc4_ksa(bytes(bad))
    must(bad_calc != state[:256], f"negative KSA control rejects mutated {ioctl}")

# PRGA replay checks for useful non-zero calls.
useful = ["prga_001", "prga_009", "prga_010", "prga_011"]

for prga in useful:
    d = ROOT / prga
    before_state = (d / "state_before_sij.bin").read_bytes()
    after_state = (d / "state_after_sij.bin").read_bytes()
    before_out = (d / "output_before.bin").read_bytes()
    after_out = (d / "output_after.bin").read_bytes()

    # The useful region is 20 bytes.
    calc_out20, calc_state = rc4_prga_xor(before_state, before_out[:20])

    must(calc_out20 == after_out[:20], f"{prga} PRGA output replay matches first 20 bytes")
    must(calc_state[:258] == after_state[:258], f"{prga} PRGA state replay matches S+i+j")

    # Negative control: mutate one byte of the pre-state; replay must fail.
    bad_state = bytearray(before_state)
    bad_state[0] ^= 1
    bad_out20, bad_after_state = rc4_prga_xor(bytes(bad_state), before_out[:20])
    must(
        bad_out20 != after_out[:20] or bad_after_state[:258] != after_state[:258],
        f"{prga} negative PRGA control rejects mutated state"
    )

print("[AUDIT RESULT] PASS")
