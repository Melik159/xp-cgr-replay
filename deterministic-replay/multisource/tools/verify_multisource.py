#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, csv, hashlib, json, re, subprocess, sys, tempfile, time
from pathlib import Path


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_cases(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def run(cmd, capture=False):
    if capture:
        return subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    subprocess.run(cmd, check=True)
    return ""


def mutate_sources(src: dict, ev: int, name: str, off: int, val: int) -> dict:
    x = copy.deepcopy(src)
    raw = bytearray.fromhex(x["ksec_events"][ev]["sources"][name])
    raw[off] = val
    x["ksec_events"][ev]["sources"][name] = raw.hex()
    return x


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package-root", type=Path, required=True)
    ap.add_argument("--rust-bin", type=Path, required=True)
    ap.add_argument("--cuda-bin", type=Path, required=True)
    ap.add_argument("--fixture", type=Path, required=True)
    ap.add_argument("--cases", type=Path, required=True)
    ap.add_argument("--run", default="run1")
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--case-limit", type=int)
    ap.add_argument("--python-check", choices=("none","sample","full"), default="sample")
    ap.add_argument("--python-samples", default="0,85,170,255,original")
    ap.add_argument("--threads", type=int, default=32)
    a = ap.parse_args()

    root = a.package_root.resolve()
    cases = load_cases(a.cases)
    if a.case_limit:
        cases = cases[:a.case_limit]
    out = a.out_dir.resolve(); out.mkdir(parents=True, exist_ok=True)
    golden = out / "golden"; golden.mkdir(exist_ok=True)

    state = src = model = None
    if a.python_check != "none":
        bundle_root = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(bundle_root / "oracle"))
        import model as model_mod  # type: ignore
        model = model_mod
        rd = root / "fixtures" / a.run
        state = json.loads((rd / "state_before.json").read_text(encoding="utf-8"))
        src = json.loads((rd / "sources.json").read_text(encoding="utf-8"))

    rows = []
    failures = 0
    t_all = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="cgr_ms_") as td0:
        td = Path(td0)
        for idx, case in enumerate(cases, 1):
            cid = case["id"]; ev = int(case["event"]); name = case["source"]; off = int(case["offset"])
            rj = td / "rust.jsonl"; cb = td / "cuda.bin"
            for p in (rj, cb):
                if p.exists(): p.unlink()

            search = f"ksec:{ev}:{name}:{off}:{off+1}"
            rust_cmd = [str(a.rust_bin), "--fixtures-root", str(root), "--run", a.run,
                        "--boundary", "pre_acquisition", "--search", search, "--values", "0:255",
                        "--max-trials", "256", "--threads", "auto", "--progress", "0", "--results", str(rj)]
            t0 = time.perf_counter(); rust_stdout = run(rust_cmd, capture=True); rust_wall = time.perf_counter()-t0
            rust_records = [json.loads(x) for x in rj.read_text(encoding="utf-8").splitlines() if x.strip()]
            if len(rust_records) != 256:
                raise SystemExit(f"{cid}: rust produced {len(rust_records)} records")
            rust_bytes = b"".join(bytes.fromhex(r["output_hex"]) for r in rust_records)
            (golden / f"{cid}.bin").write_bytes(rust_bytes)

            cuda_cmd = [str(a.cuda_bin), "--fixture", str(a.fixture), "--event", str(ev),
                        "--source", name, "--offset", str(off), "--values", "0:255",
                        "--max-trials", "256", "--threads", str(a.threads), "--dump", str(cb)]
            t0 = time.perf_counter(); cuda_stdout = run(cuda_cmd, capture=True); cuda_wall = time.perf_counter()-t0
            cuda_bytes = cb.read_bytes()
            rc_exact = cuda_bytes == rust_bytes and len(cuda_bytes) == 8192

            py_checked = 0; py_exact = True
            if a.python_check != "none":
                assert state is not None and src is not None and model is not None
                if a.python_check == "full":
                    vals = list(range(256))
                else:
                    vals = []
                    for tok in a.python_samples.split(","):
                        tok = tok.strip()
                        v = int(case["original_value"]) if tok == "original" else int(tok, 0)
                        if 0 <= v <= 255 and v not in vals: vals.append(v)
                for v in vals:
                    pred = model.predict(state, mutate_sources(src, ev, name, off, v))
                    po = bytes.fromhex(pred["predicted_output_hex"])
                    ro = bytes.fromhex(rust_records[v]["output_hex"])
                    if po != ro:
                        py_exact = False
                        break
                    py_checked += 1

            orig = int(case["original_value"])
            original_output = bytes.fromhex(rust_records[orig]["output_hex"])
            rd = root / "fixtures" / a.run
            obs_path = rd / "observed.json"
            if obs_path.exists():
                obs = json.loads(obs_path.read_text(encoding="utf-8"))
                baseline = bytes.fromhex(obs["output_hex"])
            else:
                historical = {
                    "run1": "a37bf2d7c0c473fc92c62f5171adb25cabdb23a5bb9fcc6b3bd733aaeac53ad4",
                    "run2": "73f3bee078d1335c3dda75994b505be400b1b29ecf2443000cf83128dfcd2fd8",
                }
                baseline = bytes.fromhex(historical[a.run])
            orig_ok = original_output == baseline

            m = re.search(r"rate=([0-9.eE+-]+)", cuda_stdout)
            cuda_rate = float(m.group(1)) if m else 0.0
            ok = rc_exact and py_exact and orig_ok
            failures += 0 if ok else 1
            rows.append({
                "id": cid, "event": ev, "source": name, "offset": off,
                "original_value": orig, "rust_sha256": sha256(rust_bytes), "cuda_sha256": sha256(cuda_bytes),
                "rust_cuda_exact": "YES" if rc_exact else "NO",
                "python_checked": py_checked, "python_exact": "YES" if py_exact else "NO",
                "original_matches_baseline": "YES" if orig_ok else "NO",
                "rust_wall_s": f"{rust_wall:.6f}", "cuda_wall_s": f"{cuda_wall:.6f}",
                "cuda_kernel_rate": f"{cuda_rate:.3f}", "status": "PASS" if ok else "FAIL",
            })
            print(f"[{idx:03d}/{len(cases):03d}] {cid:<28} rust==cuda={'YES' if rc_exact else 'NO'} python={py_checked}:{'PASS' if py_exact else 'FAIL'} orig={'PASS' if orig_ok else 'FAIL'}")
            if not ok:
                print("CUDA stdout:\n" + cuda_stdout)
                print("Rust stdout:\n" + rust_stdout)
                break

    csv_path = out / "multisource_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["status"])
        w.writeheader(); w.writerows(rows)
    elapsed = time.perf_counter()-t_all
    manifest = {
        "schema": "cgr-multisource-validation/v1",
        "run": a.run, "cases_requested": len(cases), "cases_completed": len(rows),
        "candidate_outputs_compared_rust_cuda": len(rows)*256,
        "python_outputs_checked": sum(int(r["python_checked"]) for r in rows),
        "failures": failures, "elapsed_wall_s": elapsed,
        "results_csv": str(csv_path),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    if failures:
        print(f"MULTISOURCE_VERIFY FAIL failures={failures} completed={len(rows)}/{len(cases)}")
        return 1
    print(f"MULTISOURCE_VERIFY PASS cases={len(rows)} rust_cuda_outputs={len(rows)*256} python_checked={manifest['python_outputs_checked']} elapsed={elapsed:.2f}s")
    print(f"results={csv_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
