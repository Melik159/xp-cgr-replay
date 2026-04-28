#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def b58encode(b: bytes) -> str:
    n_zeros = len(b) - len(b.lstrip(b"\0"))
    num = int.from_bytes(b, "big")
    s = ""
    while num:
        num, rem = divmod(num, 58)
        s = B58_ALPHABET[rem] + s
    return "1" * n_zeros + s


def b58check(version: bytes, payload: bytes) -> str:
    data = version + payload
    chk = sha256(sha256(data))[:4]
    return b58encode(data + chk)


def private_key_to_wif(secret_hex: str, compressed: bool) -> str:
    payload = bytes.fromhex(secret_hex)
    if compressed:
        payload += b"\x01"
    return b58check(b"\x80", payload)


def pubkey_to_p2pkh(pubkey_hex: str) -> str:
    pub = bytes.fromhex(pubkey_hex)
    h160 = ripemd160(sha256(pub))
    return b58check(b"\x00", h160)


def spaced(hexstr: str) -> str:
    return " ".join(hexstr[i:i + 2] for i in range(0, len(hexstr), 2))


def load_rand_after(path: Path) -> str:
    matches = []

    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue

        obj = json.loads(line)

        if obj.get("source") == "ssleay_rand_bytes" and obj.get("stage") == "after":
            data = obj["data"].upper()
            data_len = obj.get("data_len")

            if len(data) != 64:
                raise ValueError(f"{path}:{lineno}: data is not 32 bytes")

            if data_len != 32:
                raise ValueError(f"{path}:{lineno}: data_len != 32")

            bytes.fromhex(data)
            matches.append(data)

    if not matches:
        raise ValueError(f"no ssleay_rand_bytes/after entry found in {path}")

    if len(matches) > 1:
        raise ValueError(f"multiple ssleay_rand_bytes/after entries found in {path}")

    return matches[0]


def load_expected(log_path: Path, explicit_path: str | None) -> dict:
    if explicit_path:
        path = Path(explicit_path)
    else:
        path = log_path.parent / "expected.json"

    if not path.exists():
        return {}

    return json.loads(path.read_text(encoding="utf-8"))


def ok(label: str, got: str, expected: str | None) -> bool:
    if expected is None:
        print(f"{label}: SKIPPED")
        return True

    status = got.upper() == expected.upper()
    print(f"{label}: {'YES' if status else 'NO'}")
    if not status:
        print(f"  got     : {got}")
        print(f"  expected: {expected}")
    return status


def line() -> None:
    print("-" * 80)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="sampleXX/prng_log_excerpt.jsonl")
    ap.add_argument("--expected", help="optional expected.json path")
    args = ap.parse_args()

    log_path = Path(args.log)
    expected = load_expected(log_path, args.expected)

    rand_hex = load_rand_after(log_path)
    secret_hex = rand_hex

    wif_uncomp = private_key_to_wif(secret_hex, compressed=False)
    wif_comp = private_key_to_wif(secret_hex, compressed=True)

    pub_u = expected.get("pubkey_uncompressed_hex")
    pub_c = expected.get("pubkey_compressed_hex")

    addr_u = pubkey_to_p2pkh(pub_u) if pub_u else None
    addr_c = pubkey_to_p2pkh(pub_c) if pub_c else None

    print("RAND → SECRET → WIF → ADDRESS")
    line()
    print(f"Input file: {log_path}")
    print(f"Expected : {log_path.parent / 'expected.json'}")
    line()

    print("RAND bytes from ssleay_rand_bytes/after (32):")
    print(" " + spaced(rand_hex))
    line()

    print("SECRET candidate:")
    print(" " + secret_hex)
    secret_ok = ok("Match RAND==SECRET", secret_hex, expected.get("secret_hex") or rand_hex)
    line()

    print(f"WIF (uncompressed): {wif_uncomp}")
    print(f"WIF (compressed)  : {wif_comp}")
    wif_u_ok = ok("WIF uncompressed OK", wif_uncomp, expected.get("wif_uncompressed"))
    wif_c_ok = ok("WIF compressed OK  ", wif_comp, expected.get("wif_compressed"))

    addr_u_ok = True
    addr_c_ok = True

    if pub_u:
        line()
        print("PubKey (uncompressed):")
        print(" " + pub_u)
        print(f"Address (expected): {expected.get('address_uncompressed')}")
        print(f"Address (recalc)  : {addr_u}")
        addr_u_ok = ok("Address uncomp OK", addr_u, expected.get("address_uncompressed"))

    if pub_c:
        line()
        print("PubKey (compressed):")
        print(" " + pub_c)
        print(f"Address (expected): {expected.get('address_compressed')}")
        print(f"Address (recalc)  : {addr_c}")
        addr_c_ok = ok("Address comp OK  ", addr_c, expected.get("address_compressed"))

    line()
    print("Summary:")
    print(f" - RAND==SECRET:   {'OK' if secret_ok else 'MISMATCH'}")
    print(f" - WIF uncomp:     {'OK' if wif_u_ok else 'MISMATCH'}")
    print(f" - WIF comp:       {'OK' if wif_c_ok else 'MISMATCH'}")
    print(f" - P2PKH uncomp:   {'OK' if addr_u_ok else 'MISMATCH'}")
    print(f" - P2PKH comp:     {'OK' if addr_c_ok else 'MISMATCH'}")
    line()

    return 0 if all([secret_ok, wif_u_ok, wif_c_ok, addr_u_ok, addr_c_ok]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
