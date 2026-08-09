#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def clean_json_line(line: str) -> str:
    line = line.strip()
    if not line:
        return ""

    # anonymized / broken first form:
    # 2876,"source":"...","stage":"...",...
    if not line.startswith("{"):
        line = '{"tid":' + line

    # tolerate trailing comma before }
    line = re.sub(r",\s*}", "}", line)

    return line


def load_jsonish_lines(path: Path):
    rows = []
    for lineno, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        line = clean_json_line(raw)
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise SystemExit(f"JSON parse error line {lineno}: {e}\n{raw[:240]}")
        rows.append(obj)
    return rows


def hexbytes(s: str) -> bytes:
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s or ""))


def xor_engine(before: bytes, digest: bytes) -> bytes:
    if len(digest) < len(before):
        raise ValueError("digest shorter than state fragment")
    return bytes(b ^ digest[i] for i, b in enumerate(before))


def get_first(rows, stage):
    for r in rows:
        if r.get("stage") == stage:
            return r
    return None


def get_all(rows, stage):
    return [r for r in rows if r.get("stage") == stage]


def main():
    ap = argparse.ArgumentParser(
        description="Independent ssleay_rand_bytes replay from anonymized JSONL"
    )
    ap.add_argument("log", help="anonymized ssleay_stir2randbytes JSONL/log")
    ap.add_argument(
        "--index",
        type=int,
        default=None,
        help="state[] start index to use. Default: value from state_index_after_stir",
    )
    ap.add_argument(
        "--out-len",
        type=int,
        default=32,
        help="number of RAND bytes to reconstruct, default 32",
    )
    args = ap.parse_args()

    rows = load_jsonish_lines(Path(args.log))

    state_row = get_first(rows, "state_after_stir")
    if not state_row:
        raise SystemExit("missing stage=state_after_stir")

    state = hexbytes(state_row["data"])

    idx_row = get_first(rows, "state_index_after_stir")
    num_row = get_first(rows, "state_num_after_stir")
    snap_row = get_first(rows, "loop_index_state_snapshot")

    logged_index = int(idx_row["value"]) if idx_row else None
    logged_num = int(num_row["value"]) if num_row else None
    chosen_index = args.index if args.index is not None else logged_index

    if chosen_index is None:
        raise SystemExit("no --index supplied and no state_index_after_stir in log")

    print("ssleay_rand_bytes independent replay")
    print("-" * 72)
    print(f"records              : {len(rows)}")
    print(f"state_after_stir len : {len(state)}")
    print(f"logged index         : {logged_index}")
    print(f"logged num           : {logged_num}")
    print(f"snapshot             : {snap_row.get('st_idx/st_num') if snap_row else None}")
    print(f"selected index       : {chosen_index}")
    print()

    # Build iterations sequentially.
    # Important: stage names may repeat rand_bytes_iter_0_* for all iterations.
    iterations = []
    cur = {}

    for r in rows:
        stage = r.get("stage", "")

        if stage == "rand_bytes_iter_0_input_local_md":
            if cur:
                iterations.append(cur)
            cur = {"local_md": hexbytes(r["data"])}

        elif stage == "rand_bytes_iter_0_input_md_c":
            cur["md_c"] = hexbytes(r["data"])

        elif stage == "rand_bytes_iter_0_input_buf":
            cur["buf"] = hexbytes(r["data"])

        elif stage == "rand_bytes_iter_state":
            cur["logged_state"] = hexbytes(r["data"])

        elif stage == "rand_bytes_iter_0_output_md":
            cur["logged_md"] = hexbytes(r["data"])

        else:
            m_xor = re.match(r"rand_bytes_iter_0_state_xor_(\d+)$", stage)
            if m_xor:
                cur.setdefault("logged_xor", {})[int(m_xor.group(1))] = hexbytes(r["data"])
                continue

            m_out = re.match(r"rand_bytes_iter_0_output_byte_(\d+)$", stage)
            if m_out:
                cur.setdefault("logged_out", {})[int(m_out.group(1))] = hexbytes(r["data"])
                continue

    if cur:
        iterations.append(cur)

    print(f"iterations found     : {len(iterations)}")
    print()

    out = bytearray()
    errors = []

    pos = chosen_index

    for i, it in enumerate(iterations):
        required = ["local_md", "md_c", "buf", "logged_state", "logged_md"]
        missing = [k for k in required if k not in it]
        if missing:
            errors.append(f"iter {i}: missing fields {missing}")
            continue

        take_state = len(it["logged_state"])
        state_slice = state[pos:pos + take_state]

        print(f"=== Iteration {i} ===")
        print(f"state offset          : {pos}")
        print(f"state slice           : {state_slice.hex().upper()}")
        print(f"logged iter_state     : {it['logged_state'].hex().upper()}")

        if state_slice != it["logged_state"]:
            errors.append(
                f"iter {i}: state slice mismatch at offset {pos}: "
                f"calc={state_slice.hex().upper()} log={it['logged_state'].hex().upper()}"
            )

        md_input = it["local_md"] + it["md_c"] + it["buf"] + state_slice
        calc_md = hashlib.sha1(md_input).digest()

        print(f"calc output_md        : {calc_md.hex().upper()}")
        print(f"logged output_md      : {it['logged_md'].hex().upper()}")

        if calc_md != it["logged_md"]:
            errors.append(
                f"iter {i}: output_md mismatch: "
                f"calc={calc_md.hex().upper()} log={it['logged_md'].hex().upper()}"
            )

        state_after = xor_engine(state_slice, calc_md)
        print(f"xor state_after       : {state_after.hex().upper()}")

        for j, b in enumerate(state_slice):
            calc_pair = bytes([b, state_after[j]])
            log_pair = it.get("logged_xor", {}).get(j)
            if log_pair is not None and calc_pair != log_pair:
                errors.append(
                    f"iter {i}: state_xor_{j} mismatch: "
                    f"calc={calc_pair.hex().upper()} log={log_pair.hex().upper()}"
                )

        # OpenSSL takes digest[10:20] into output, truncated to requested length.
        produced = calc_md[10:20]
        remaining = args.out_len - len(out)
        produced = produced[:max(0, remaining)]
        out.extend(produced)

        for j, b in enumerate(produced):
            log_b = it.get("logged_out", {}).get(j)
            if log_b is not None and bytes([b]) != log_b:
                errors.append(
                    f"iter {i}: output_byte_{j} mismatch: "
                    f"calc={b:02X} log={log_b.hex().upper()}"
                )

        print(f"produced RAND bytes   : {produced.hex().upper()}")
        print()

        pos += take_state

        if len(out) >= args.out_len:
            break

    after_rows = get_all(rows, "after")
    if after_rows:
        logged_after = hexbytes(after_rows[-1]["data"])
        print("Final")
        print("-" * 72)
        print(f"calc after            : {out.hex().upper()}")
        print(f'logged stage "after"  : {logged_after[:args.out_len].hex().upper()}')

        if out != logged_after[:args.out_len]:
            errors.append(
                f'final stage "after" mismatch: '
                f"calc={out.hex().upper()} log={logged_after[:args.out_len].hex().upper()}"
            )
    else:
        print('warning: no stage "after" found')

    print()
    if errors:
        print("VALIDATION: FAIL")
        for e in errors:
            print(" -", e)
        sys.exit(1)

    print("VALIDATION: PASS")


if __name__ == "__main__":
    main()
