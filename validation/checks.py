from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from .common import (
    Outcome,
    ValidationError,
    file_hashes,
    load_jsonl,
    rc4_ksa,
    rc4_xor,
    require,
    require_text,
    run_command,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "evidence" / "components"
CAMPAIGNS = ROOT / "evidence" / "campaigns"


def check_windows_inputs() -> Outcome:
    root = COMPONENTS / "windows-rand-poll"
    proc = run_command(
        ["python3", "decode_randwin_full.py", ".", "--recursive", "--summary", "--validate"],
        cwd=root,
    )
    require(proc.stdout.count("VALIDATION: PASS") == 3, "expected three valid RAND_poll captures")
    return Outcome("Windows RAND_poll inputs", "3 captured runs pass structural validation (warnings retained)")


def check_kernel_vlh() -> Outcome:
    root = COMPONENTS / "kernel-vlh"
    proc = run_command(["python3", "validate_vlh_campaign.py"], cwd=root)
    for marker in ("MAPPING_PASS: True", "SEED_PASS: True", "[PASS] True"):
        require_text(proc.stdout, marker)
    return Outcome("Kernel VLH replay", "pool mapping and seedbase_after are reproduced exactly")


def check_v18_kernel_boundary() -> Outcome:
    root = CAMPAIGNS / "03-ksecdd-to-advapi"
    ksec = sorted(root.glob("samples/ksec_*/V18_1_MANUAL_KSEC_KERNEL_OUTBUF_100.bin"))
    ioctl = sorted(root.glob("samples/ioctl_*/V18_1_IOCTL_OUTBUF_100.bin"))
    require(len(ksec) == 1 and len(ioctl) == 8, "V18.1 sample cardinality mismatch")
    matches = sum(a.read_bytes()[:256] == b.read_bytes()[:256] for a in ksec for b in ioctl)
    require(matches == 1, f"expected one KSecDD/ADVAPI match, got {matches}")

    with tempfile.TemporaryDirectory(prefix="v18-parse-") as tmp:
        tmpdir = Path(tmp)
        proc = run_command(
            [
                "python3", "tools/parse_seed2state_v18_1.py",
                "capture/sample01.REDACTED.log",
                "--samples", str(tmpdir / "samples"),
                "--jsonl", str(tmpdir / "events.jsonl"),
            ],
            cwd=root,
        )
        require(proc.returncode == 0, "V18.1 parser failed")
        published_bins = {
            rel: digest for rel, digest in file_hashes(root / "samples").items() if rel.endswith(".bin")
        }
        generated_bins = {
            rel: digest for rel, digest in file_hashes(tmpdir / "samples").items() if rel.endswith(".bin")
        }
        for rel, digest in published_bins.items():
            require(generated_bins.get(rel) == digest, f"V18.1 regenerated binary mismatch: {rel}")
        require((tmpdir / "events.jsonl").read_bytes() == (root / "reports/sample01.events.jsonl").read_bytes(),
                "V18.1 regenerated event stream differs from the retained report")
    return Outcome("V18.1 KSecDD to ADVAPI", "1 exact 256-byte boundary match; published binaries regenerate from the log")


def _event_dump_sha(event: dict | None, marker: str) -> str | None:
    if not event:
        return None
    dump = event.get("dumps", {}).get(marker)
    return dump.get("sha256") if dump else None


def check_v20_transport() -> Outcome:
    root = CAMPAIGNS / "05-newgenrandom-transport"
    with tempfile.TemporaryDirectory(prefix="v20-parse-") as tmp:
        tmpdir = Path(tmp)
        run_command(
            [
                "python3", "tools/parse_seed2state_v20_1.py",
                "capture/sample01.REDACTED.log",
                "--samples", str(tmpdir / "samples"),
                "--jsonl", str(tmpdir / "events.jsonl"),
            ],
            cwd=root,
        )
        require(file_hashes(tmpdir / "samples") == file_hashes(root / "samples"),
                "V20.1 regenerated samples differ from retained samples")
        require((tmpdir / "events.jsonl").read_bytes() == (root / "reports/sample01.events.jsonl").read_bytes(),
                "V20.1 regenerated event stream differs from retained events")
        events = load_jsonl(tmpdir / "events.jsonl")

    markers = (
        ("V20_1_NEWGENEX_AFTER_GATHER_F74599A6", "V20_1_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100"),
        ("V20_1_NEWGENEX_PRE_RETURN_F74599C8", "V20_1_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100"),
        ("V20_1_ADVAPI_IOCTL_AFTER_C2", "V20_1_ADVAPI_IOCTL_OUTBUF_100"),
    )
    observations = []
    for event in events:
        for event_marker, dump_marker in markers:
            if event.get("marker") == event_marker:
                observations.append((event_marker, _event_dump_sha(event, dump_marker)))
    require(len(observations) == 24, f"expected 24 V20.1 transport observations, got {len(observations)}")
    outputs = []
    for offset in range(0, 24, 3):
        triple = observations[offset:offset + 3]
        require([item[0] for item in triple] == [item[0] for item in markers],
                f"V20.1 event order mismatch in triple {offset // 3 + 1}")
        hashes = [item[1] for item in triple]
        require(hashes[0] is not None and len(set(hashes)) == 1,
                f"V20.1 byte mismatch in triple {offset // 3 + 1}")
        outputs.append(hashes[0])
    require(len(set(outputs)) == 8, "V20.1 outputs are not eight distinct buffers")
    return Outcome("V20.1 NewGenRandom transport", "8 distinct 256-byte after/pre-return/ADVAPI triplets match")


def check_v22_first_write() -> Outcome:
    root = CAMPAIGNS / "06-newgenrandom-first-write"
    events = load_jsonl(root / "reports/v22_writer_events.jsonl")
    cycles = []
    current = None
    for event in events:
        marker = event.get("marker")
        if marker == "V22_WRITER_NEWGENEX_ENTRY_F7459951":
            require(current is None, "V22 cycle ended without ADVAPI observation")
            current = {"entry": event}
        elif current is not None and marker == "V22_WRITER_OUTBUF_FIRST_WRITE":
            current["writer"] = event
        elif current is not None and marker == "V22_WRITER_NEWGENEX_AFTER_GATHER_F74599A6":
            current["after"] = event
        elif current is not None and marker == "V22_WRITER_NEWGENEX_PRE_RETURN_F74599C8":
            current["pre"] = event
        elif current is not None and marker in ("V22_WRITER_ADVAPI_IOCTL_AFTER_C2", "V22_1_ADVAPI_IOCTL_AFTER_C2"):
            current["advapi"] = event
            cycles.append(current)
            current = None
    require(current is None and len(cycles) == 8, f"expected 8 complete V22 cycles, got {len(cycles)}")

    available_hashes = {sha256_file(path) for path in (root / "samples").rglob("*.bin")}
    for event in events:
        for dump in event.get("dumps", {}).values():
            digest = dump.get("sha256")
            if digest:
                require(digest in available_hashes, f"V22 event dump has no retained binary: {digest}")

    eips = set()
    for number, cycle in enumerate(cycles, 1):
        require(all(name in cycle for name in ("writer", "after", "pre", "advapi")),
                f"V22 cycle {number} is structurally incomplete")
        writer_sha = _event_dump_sha(cycle["writer"], "V22_WRITER_OUTBUF_AT_FIRST_WRITE_100")
        require(writer_sha in available_hashes, f"V22 cycle {number} writer buffer is not retained")
        hashes = (
            _event_dump_sha(cycle["after"], "V22_WRITER_KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100"),
            _event_dump_sha(cycle["pre"], "V22_WRITER_KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100"),
            _event_dump_sha(cycle["advapi"], "V22_WRITER_ADVAPI_IOCTL_OUTBUF_100")
            or _event_dump_sha(cycle["advapi"], "V22_1_ADVAPI_IOCTL_OUTBUF_100"),
        )
        require(hashes[0] is not None and len(set(hashes)) == 1,
                f"V22 cycle {number} transport mismatch")
        eips.add(cycle["writer"].get("kv", {}).get("eip"))
    require(eips == {"f745f10b"}, f"unexpected V22 first-writer EIP set: {sorted(eips)}")
    return Outcome("V22 first-write observation", "8 complete cycles; writer buffers retained; writer EIP f745f10b; transport matches")


def check_v23_transport() -> Outcome:
    root = CAMPAIGNS / "07-ksecdd-rc4-transport"
    proc = run_command(
        ["python3", "tools/validate_v23_transport.py", "reports/v23_events.jsonl"],
        cwd=root,
    )
    require_text(proc.stdout, "PASS=8/8")
    hashes = {sha256_file(path) for path in (root / "samples").rglob("*.bin")}
    for event in load_jsonl(root / "reports/v23_events.jsonl"):
        for dump in event.get("dumps", {}).values():
            digest = dump.get("sha256")
            if digest:
                require(digest in hashes, f"V23 event dump has no retained binary: {digest}")
    return Outcome("V23 KSecDD RC4 transport", "8 structurally complete cycles pass and every event hash resolves to a sample")


def check_v24_partial_transport() -> Outcome:
    root = CAMPAIGNS / "08-partial-advapi-transport"
    events = load_jsonl(root / "reports/v24_events.jsonl")
    key_lengths = [
        int(event["eval"]["dec"])
        for event in events
        if event.get("marker") == "V24_CLOSEG_RC4_KEY_ARG_KEYLEN_T9" and event.get("eval")
    ]
    prga_lengths = [
        int(event["eval"]["dec"])
        for event in events
        if event.get("marker") == "V24_CLOSEG_RC4_ARG_LEN_T5" and event.get("eval")
    ]
    require(len(key_lengths) == len(prga_lengths) == 16, "V24 retained events do not describe 16 RC4 calls")

    for index, (key_length, prga_length) in enumerate(zip(key_lengths, prga_lengths), 1):
        prefix = f"{index:03d}_V24_CLOSEG_"
        key = (root / "samples" / f"{prefix}RC4_KEY_KEYBUF_100.bin").read_bytes()
        state_entry = (root / "samples" / f"{prefix}RC4_STATE_ENTRY_120.bin").read_bytes()
        before = (root / "samples" / f"{prefix}RC4_OUTBUF_BEFORE_100.bin").read_bytes()
        returned = (root / "samples" / f"{prefix}RC4_OUTBUF_RETURN_100.bin").read_bytes()
        state_return = (root / "samples" / f"{prefix}RC4_STATE_RETURN_120.bin").read_bytes()
        require(rc4_ksa(key[:key_length]) == state_entry[:256], f"V24 KSA mismatch at call {index}")
        replay, new_state = rc4_xor(state_entry, before[:prga_length])
        require(replay == returned[:prga_length], f"V24 PRGA output mismatch at call {index}")
        require(new_state == state_return[:258], f"V24 PRGA state mismatch at call {index}")

    for index in range(1, 9):
        prefix = f"{index:03d}_V24_CLOSEG_"
        after = (root / "samples" / f"{prefix}KSEC_NEWGENEX_OUTBUF_AFTER_GATHER_100.bin").read_bytes()
        before_return = (root / "samples" / f"{prefix}KSEC_NEWGENEX_OUTBUF_PRE_RETURN_100.bin").read_bytes()
        require(len(after) >= 256 and after[:256] == before_return[:256],
                f"V24 after/pre-return mismatch at cycle {index}")

    advapi_files = sorted((root / "samples").glob("*_V24_CLOSEG_ADVAPI_IOCTL_OUTBUF_100.bin"))
    require(len(advapi_files) == 7, "V24 retained ADVAPI artifact count changed")
    return Outcome(
        "V24 partial ADVAPI transport",
        "16 KSA and 16 PRGA calls replay; 8 after/pre-return pairs match; full ADVAPI buffer remains unavailable",
        status="PARTIAL",
    )


def check_v5_round_robin() -> Outcome:
    root = CAMPAIGNS / "01-advapi-round-robin"
    result = next((root / "reports").glob("*.result.json"))
    proc = run_command(
        ["python3", "tools/replay_seed2state_v5_roundrobin.py", str(result), "--dump-select"],
        cwd=root,
    )
    require_text(proc.stdout, "[RESULT] PASS")
    return Outcome("V5 ADVAPI round-robin", "manager modulo-8, useful PRGA, SystemFunction036, and aux20 relations pass")


def check_v17_ioctl_to_rc4() -> Outcome:
    root = CAMPAIGNS / "02-advapi-ioctl-to-rc4"
    with tempfile.TemporaryDirectory(prefix="v17-parse-") as tmp:
        tmpdir = Path(tmp)
        run_command(
            [
                "python3", "tools/parse_seed2state_v17_1_precise.py",
                "capture/sample01.log",
                "--jsonl", str(tmpdir / "events.jsonl"),
                "--samples", str(tmpdir / "samples"),
            ],
            cwd=root,
        )
        require(file_hashes(tmpdir / "samples") == file_hashes(root / "samples"),
                "V17.1 regenerated samples differ from retained samples")

    samples = root / "samples"
    mapping = {
        "prga_001": "ioctl_01", "prga_002": "ioctl_02", "prga_003": "ioctl_03",
        "prga_004": "ioctl_04", "prga_005": "ioctl_05", "prga_006": "ioctl_06",
        "prga_007": "ioctl_07", "prga_008": "ioctl_08", "prga_010": "ioctl_02",
        "prga_011": "ioctl_03",
    }
    for prga, ioctl in mapping.items():
        key = (samples / ioctl / "V17_1_IOCTL_OUTBUF_100.bin").read_bytes()
        observed = (samples / prga / "state_before_sij.bin").read_bytes()[:256]
        require(rc4_ksa(key) == observed, f"V17.1 KSA mismatch: {ioctl} -> {prga}")
        mutated = bytes((key[0] ^ 1,)) + key[1:]
        require(rc4_ksa(mutated) != observed, f"V17.1 negative KSA control failed: {ioctl}")

    useful = ("prga_001", "prga_009", "prga_010", "prga_011")
    for name in useful:
        sample = samples / name
        state_before = (sample / "state_before_sij.bin").read_bytes()
        before = (sample / "output_before.bin").read_bytes()[:20]
        expected = (sample / "output_after.bin").read_bytes()[:20]
        expected_state = (sample / "state_after_sij.bin").read_bytes()[:258]
        output, state = rc4_xor(state_before, before)
        require(output == expected and state == expected_state, f"V17.1 PRGA mismatch: {name}")
        mutated = bytes((state_before[0] ^ 1,)) + state_before[1:]
        bad_output, bad_state = rc4_xor(mutated, before)
        require(bad_output != expected or bad_state != expected_state,
                f"V17.1 negative PRGA control failed: {name}")
    return Outcome("V17.1 ADVAPI IOCTL to RC4", "10 direct KSA relations, 4 PRGA replays, and mutation controls pass")


def check_v18_advapi_rc4() -> Outcome:
    root = CAMPAIGNS / "03-ksecdd-to-advapi"
    ioctls = [(path.parent.name, path.read_bytes()[:256]) for path in sorted(root.glob("samples/ioctl_*/V18_1_IOCTL_OUTBUF_100.bin"))]
    states = []
    for directory in sorted((root / "samples").glob("prga_*")):
        path = directory / "state_before_sij.bin"
        if path.exists():
            states.append((directory.name, path.read_bytes()))
    matches = sum(rc4_ksa(key) == state[:256] for _, key in ioctls for _, state in states)
    require(matches == 10, f"expected 10 V18.1 KSA matches, got {matches}")
    useful = 0
    for directory in sorted((root / "samples").glob("prga_*")):
        meta = json.loads((directory / "meta.json").read_text())
        if meta.get("length") != "00000014":
            continue
        output, state = rc4_xor(
            (directory / "state_before_sij.bin").read_bytes(),
            (directory / "output_before.bin").read_bytes()[:20],
        )
        require(output == (directory / "output_after.bin").read_bytes()[:20], f"V18.1 PRGA output mismatch: {directory.name}")
        require(state == (directory / "state_after_sij.bin").read_bytes()[:258], f"V18.1 PRGA state mismatch: {directory.name}")
        useful += 1
    require(useful == 4, f"expected four useful V18.1 PRGA calls, got {useful}")
    return Outcome("V18.1 downstream ADVAPI RC4", "10 KSA matches and 4 useful PRGA calls replay")


def check_v19_provider_update() -> Outcome:
    root = CAMPAIGNS / "04-provider-state-update"
    with tempfile.TemporaryDirectory(prefix="v19-parse-") as tmp:
        calls = Path(tmp) / "calls.jsonl"
        run_command(
            ["python3", "tools/parse_seed2state_v19c.py", "capture/sample01.REDACTED.log", "--jsonl", str(calls)],
            cwd=root,
        )
        require(calls.read_bytes() == (root / "reports/sample01.calls.jsonl").read_bytes(),
                "V19c regenerated calls differ from retained calls")
        proc = run_command(["python3", "tools/replay_v19c_state20_update.py", str(calls)], cwd=root)
    for marker in ("complete_calls=5", "replay_ok=5/5", "recurrence_match=4/4", "v19c_provider_state_update_closed=True"):
        require_text(proc.stdout, marker)
    return Outcome("V19c provider state update", "5 complete provider calls replay; 4 state recurrences match")


def check_v26_provider_transition() -> Outcome:
    root = CAMPAIGNS / "09-rsaenh-provider-transition"
    parsed = run_command(
        ["python3", "tools/parse_v26_rsaenh_provider_only.py", "capture/log_excerpt_key_events.txt"],
        cwd=root,
    )
    require_text(parsed.stdout, "[PASS] OVERALL: provider-local transition validated for this log")
    replay = run_command(["python3", "tools/replay_v26_samples.py", "samples"], cwd=root)
    require_text(replay.stdout, "summary PASS=6/6")
    return Outcome("V26 rsaenh provider transition", "provider-local trace checks and 6 output-copy checks pass")


def check_v28_provider_initialization() -> Outcome:
    root = CAMPAIGNS / "10-provider-initialization"
    with tempfile.TemporaryDirectory(prefix="v28-parse-") as tmp:
        sample = Path(tmp) / "sample"
        run_command(
            [
                "python3", "tools/parse_seed2state_v28_provider_init_auxmix.py",
                "capture/g_state_init_aux_confirm.redacted.log",
                "--write-sample", str(sample),
                "--json", str(Path(tmp) / "parse.json"),
            ],
            cwd=root,
        )
        generated = {name: digest for name, digest in file_hashes(sample).items() if name != "README.md"}
        require(generated == file_hashes(root / "samples"),
                "V28 regenerated sample differs from retained sample")
        replay = run_command(["python3", "tools/replay_v28_provider_init_auxmix.py", str(sample)], cwd=root)
    require_text(replay.stdout, "OVERALL=PASS")
    return Outcome("V28 provider initialization", "redacted log regenerates the sample and all initialization relations pass")


def check_v29_provider_bridge() -> Outcome:
    root = CAMPAIGNS / "11-provider-composed-bridge"
    with tempfile.TemporaryDirectory(prefix="v29-parse-") as tmp:
        sample = Path(tmp) / "sample"
        run_command(
            [
                "python3", "tools/parse_seed2state_v29_g_composed_provider_bridge.py",
                "capture/v29_g_composed_provider_bridge.redacted.log",
                "--write-sample", str(sample),
                "--json", str(Path(tmp) / "parse.json"),
            ],
            cwd=root,
        )
        generated = {name: digest for name, digest in file_hashes(sample).items() if name != "README.md"}
        require(generated == file_hashes(root / "samples"),
                "V29 regenerated sample differs from retained sample")
        replay = run_command(["python3", "tools/replay_v29_g_composed_provider_bridge.py", str(sample)], cwd=root)
    require_text(replay.stdout, "OVERALL=PASS")
    return Outcome("V29 composed provider bridge", "init, bridge, runtime continuity, and measured 32-byte output all pass")


def check_provider_xor() -> Outcome:
    root = COMPONENTS / "provider-xor"
    proc = run_command(
        [
            "python3", "provider_xor_fips_replay.py",
            "--state20-file", "sample01/state20.bin",
            "--local-before-file", "sample01/local_before.bin",
            "--src20-file", "sample01/src20.bin",
            "--local-after-file", "sample01/local_after.bin",
        ],
        cwd=root,
    )
    require_text(proc.stdout, "xor_match     : OK")
    return Outcome("Provider XOR", "local_before XOR src20 equals the retained local_after value")


def check_fips_sha1() -> Outcome:
    root = COMPONENTS / "fips-sha1"
    proc = run_command(
        [
            "python3", "replay_fips186_block.py",
            "sample01/p1_block64.bin", "sample01/p2_block64.bin",
            "--out40-after", "sample01/out40_after.bin",
        ],
        cwd=root,
    )
    require_text(proc.stdout, "std_match  : True")
    require_text(proc.stdout, "ns_match   : False")
    return Outcome("FIPS-style SHA-1 blocks", "standard SHA-1 compression reproduces 40 bytes; alternate transform is rejected")


def check_rc4_ksa_component() -> Outcome:
    root = COMPONENTS / "rc4-ksa"
    with tempfile.TemporaryDirectory(prefix="rc4-ksa-") as tmp:
        proc = run_command(["python3", "validate_ksa.py", "--out-dir", tmp], cwd=root)
    require_text(proc.stdout, "match       : OK")
    require_text(proc.stdout, "BIT_EXACT_MATCH: 2048 bits")
    return Outcome("RC4 KSA component", "captured S-box matches all 2048 replayed bits")


def check_openssl_rand() -> Outcome:
    root = COMPONENTS / "openssl-rand"
    decoded = run_command(["python3", "decode_workstation_stats.py", *[str(path) for path in sorted((root / "sample01_workstation").glob("*.hex"))]], cwd=root)
    require(decoded.stdout.count("StatisticsStartTime") >= 4, "workstation statistics decoder did not process four buffers")
    trace = "sample01_rand_bytes/ssleay_stir_randbytes_trace.jsonl"
    replay = run_command(["python3", "replay_rand_bytes_from_stir.py", trace, "--index", "240"], cwd=root)
    require_text(replay.stdout, "VALIDATION: PASS")
    negative = run_command(
        ["python3", "replay_rand_bytes_from_stir.py", trace, "--index", "241"],
        cwd=root,
        allowed_codes=(1,),
    )
    require_text(negative.stdout, "VALIDATION: FAIL")
    return Outcome("OpenSSL post-stir RAND", "32-byte output replays at index 240 and the index-241 control is rejected")


def _base58check(payload: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    zeros = len(data) - len(data.lstrip(b"\0"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = alphabet[remainder] + encoded
    return "1" * zeros + encoded


def _secp256k1_public_keys(secret: bytes) -> tuple[bytes, bytes]:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    generator = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    scalar = int.from_bytes(secret, "big")
    require(1 <= scalar < n, "wallet secret is outside the secp256k1 scalar range")

    def add(left, right):
        if left is None:
            return right
        if right is None:
            return left
        x1, y1 = left
        x2, y2 = right
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if left == right:
            slope = (3 * x1 * x1) * pow(2 * y1, -1, p) % p
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (slope * slope - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p
        return x3, y3

    result = None
    addend = generator
    value = scalar
    while value:
        if value & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        value >>= 1
    require(result is not None, "secp256k1 multiplication returned infinity")
    x, y = result
    xb = x.to_bytes(32, "big")
    yb = y.to_bytes(32, "big")
    return b"\x04" + xb + yb, bytes((2 | (y & 1),)) + xb


def _p2pkh(public_key: bytes) -> str:
    sha = hashlib.sha256(public_key).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return _base58check(b"\x00" + ripe)


def check_bitcoin_wallet() -> Outcome:
    root = COMPONENTS / "bitcoin-wallet"
    expected = json.loads((root / "sample01/expected.json").read_text())
    wallet_events = load_jsonl(root / "sample01/prng_log_excerpt.jsonl")
    after = [event for event in wallet_events if event.get("source") == "ssleay_rand_bytes" and event.get("stage") == "after"]
    require(len(after) == 1, "wallet excerpt must contain one ssleay_rand_bytes/after record")
    secret = bytes.fromhex(after[0]["data"])
    require(secret.hex().upper() == expected["secret_hex"].upper(), "wallet secret differs from expected.json")

    trace_text = (COMPONENTS / "openssl-rand/sample01_rand_bytes/ssleay_stir_randbytes_trace.jsonl").read_text()
    require(f'"stage":"after","data":"{secret.hex().upper()}"' in trace_text,
            "wallet RAND bytes are not linked to the retained OpenSSL output")

    wif_uncompressed = _base58check(b"\x80" + secret)
    wif_compressed = _base58check(b"\x80" + secret + b"\x01")
    public_uncompressed, public_compressed = _secp256k1_public_keys(secret)
    require(wif_uncompressed == expected["wif_uncompressed"], "uncompressed WIF mismatch")
    require(wif_compressed == expected["wif_compressed"], "compressed WIF mismatch")
    require(public_uncompressed.hex() == expected["pubkey_uncompressed_hex"], "uncompressed public key mismatch")
    require(public_compressed.hex() == expected["pubkey_compressed_hex"], "compressed public key mismatch")
    require(_p2pkh(public_uncompressed) == expected["address_uncompressed"], "uncompressed P2PKH mismatch")
    require(_p2pkh(public_compressed) == expected["address_compressed"], "compressed P2PKH mismatch")
    return Outcome("Bitcoin wallet derivation", "OpenSSL output equals secret; secp256k1 keys, WIFs, and both P2PKH addresses derive independently")


BLOCKS = {
    "01-windows-inputs": (
        "Captured Windows RAND_poll inputs",
        (check_windows_inputs,),
    ),
    "02-kernel-entropy": (
        "Kernel entropy processing",
        (check_kernel_vlh,),
    ),
    "03-kernel-transport": (
        "KSecDD and ADVAPI transport",
        (check_v18_kernel_boundary, check_v20_transport, check_v22_first_write, check_v23_transport, check_v24_partial_transport),
    ),
    "04-advapi-rc4": (
        "ADVAPI RC4 and SystemFunction036",
        (check_v5_round_robin, check_v17_ioctl_to_rc4, check_v18_advapi_rc4),
    ),
    "05-provider-state": (
        "rsaenh provider state transitions",
        (check_v19_provider_update, check_v26_provider_transition, check_v28_provider_initialization, check_v29_provider_bridge),
    ),
    "06-provider-primitives": (
        "Provider output primitives",
        (check_provider_xor, check_fips_sha1, check_rc4_ksa_component),
    ),
    "07-openssl-rand": (
        "OpenSSL post-stir byte generation",
        (check_openssl_rand,),
    ),
    "08-bitcoin-wallet": (
        "Bitcoin wallet derivation",
        (check_bitcoin_wallet,),
    ),
}
