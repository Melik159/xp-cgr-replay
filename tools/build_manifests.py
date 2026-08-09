#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


COMPONENTS = {
    "randwin": "windows-rand-poll",
    "vlh": "kernel-vlh",
    "provider": "provider-xor",
    "fips": "fips-sha1",
    "rc4": "rc4-ksa",
    "ssleay": "openssl-rand",
    "wallet": "bitcoin-wallet",
}

CAMPAIGNS = {
    "seed2state_v5_roundrobin": "01-advapi-round-robin",
    "seed2state_v17_1_precise_ioctl_outbuf": "02-advapi-ioctl-to-rc4",
    "seed2state_v18_1_ksecdd_kernel_outbuf_manual": "03-ksecdd-to-advapi",
    "seed2state_v19c_fips_state20_update_replay": "04-provider-state-update",
    "seed2state_v20_1_precise_newgenrandomex_outbuf": "05-newgenrandom-transport",
    "seed2state_v22_writer_probe": "06-newgenrandom-first-write",
    "seed2state_v23_rc4_replay": "07-ksecdd-rc4-transport",
    "seed2state_v24_close_g_partial_advapi": "08-partial-advapi-transport",
    "seed2state_v26_rsaenh_provider_only": "09-rsaenh-provider-transition",
    "seed2state_v28_provider_init_auxmix": "10-provider-initialization",
    "seed2state_v29_g_composed_provider_bridge": "11-provider-composed-bridge",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def excluded(path: Path) -> bool:
    return (
        path.name in {"README.md", "SHA256SUMS", "run_tests.sh", "reproduce_sample01.sh"}
        or path.suffix == ".pyc"
        or path.name.endswith("~")
        or "__pycache__" in path.parts
    )


def campaign_target(name: str, relative: Path) -> Path:
    target = Path("evidence/campaigns") / CAMPAIGNS[name]
    parts = relative.parts

    if name == "seed2state_v5_roundrobin":
        head = {"parser": "tools", "results_v5": "reports", "samples": "samples"}[parts[0]]
        return target / head / Path(*parts[1:])

    if name == "seed2state_v17_1_precise_ioctl_outbuf":
        if parts[0] in {"parser", "tools"}:
            return target / "tools" / Path(*parts[1:])
        if parts[:2] == ("sample01", "raw"):
            return target / "capture" / "sample01.log"
        if parts[:2] == ("sample01", "samples"):
            return target / "samples" / Path(*parts[2:])
        if parts[:2] == ("sample01", "results"):
            return target / "reports" / Path(*parts[2:])

    simple = {
        "seed2state_v18_1_ksecdd_kernel_outbuf_manual": {
            "scripts": "tools", "logs": "capture", "reports": "reports"
        },
        "seed2state_v19c_fips_state20_update_replay": {
            "scripts": "tools", "logs": "capture", "reports": "reports"
        },
        "seed2state_v20_1_precise_newgenrandomex_outbuf": {
            "scripts": "tools", "logs": "capture", "reports": "reports"
        },
    }
    if name in simple:
        if parts[0] in simple[name]:
            return target / simple[name][parts[0]] / Path(*parts[1:])
        if name == "seed2state_v18_1_ksecdd_kernel_outbuf_manual" and parts[:3] == ("samples", "sample01", "raw"):
            return target / "samples" / Path(*parts[3:])
        if parts[:2] == ("samples", "sample01"):
            return target / "samples" / Path(*parts[2:])

    if name == "seed2state_v22_writer_probe":
        heads = {
            "parser": "tools", "tools": "tools", "samples": "samples",
            "results_v22_writer_probe": "reports", "sanity_v22_writer_probe": "provenance",
        }
        return target / heads[parts[0]] / Path(*parts[1:])

    if name in {"seed2state_v23_rc4_replay", "seed2state_v24_close_g_partial_advapi"}:
        results = "results_v23" if "v23" in name else "results_v24"
        sanity = None if "v23" in name else "sanity_v24"
        if parts[0] in {"parser", "tools"}:
            return target / "tools" / Path(*parts[1:])
        if parts[0] == results and len(parts) > 1 and parts[1] == "samples":
            return target / "samples" / Path(*parts[2:])
        if parts[0] == results:
            return target / "reports" / Path(*parts[1:])
        if sanity and parts[0] == sanity:
            return target / "provenance" / Path(*parts[1:])

    if name in {
        "seed2state_v26_rsaenh_provider_only",
        "seed2state_v28_provider_init_auxmix",
        "seed2state_v29_g_composed_provider_bridge",
    }:
        if parts[0] in {"parser", "tools"}:
            return target / "tools" / Path(*parts[1:])
        if parts[0] == "logs":
            return target / "capture" / Path(*parts[1:])
        sample_prefix = ("samples", "sample01")
        if parts[:2] == sample_prefix:
            tail = Path(*parts[2:])
            if tail.name == "log_excerpt_key_events.txt":
                return target / "capture" / tail.name
            if parts[2] == "blobs" or tail.name in {"manifest.json", "manifest.tsv"}:
                return target / "samples" / tail
            report_names = {
                "v26_provider_validation.txt": "provider_validation.txt",
                "v26_replay_samples.txt": "replay_samples.txt",
                "v28_provider_init_auxmix_validation.json": "provider_initialization_validation.json",
                "v28_provider_init_auxmix_validation.txt": "provider_initialization_validation.txt",
                "v29_g_composed_validation.json": "provider_composed_validation.json",
                "v29_g_composed_validation.txt": "provider_composed_validation.txt",
            }
            if tail.name in report_names:
                return target / "reports" / report_names[tail.name]

    raise ValueError(f"no normalized path for {name}/{relative}")


def source_mappings(source: Path, repository: Path):
    for old_name, new_name in COMPONENTS.items():
        base = source / old_name
        for path in sorted(base.rglob("*")):
            if path.is_file() and not excluded(path):
                yield path, repository / "evidence/components" / new_name / path.relative_to(base)

    campaign_root = source / "campaigns"
    for old_name in CAMPAIGNS:
        base = campaign_root / old_name
        for path in sorted(base.rglob("*")):
            if path.is_file() and not excluded(path):
                yield path, repository / campaign_target(old_name, path.relative_to(base))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build integrity and source-provenance manifests")
    parser.add_argument("--source", required=True, type=Path, help="original xp-cgr-replay-main directory")
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    source = args.source.resolve()
    repository = args.repository.resolve()

    rows = []
    seen_targets = set()
    for source_path, target_path in source_mappings(source, repository):
        if target_path in seen_targets:
            raise SystemExit(f"duplicate target mapping: {target_path}")
        seen_targets.add(target_path)
        if not target_path.is_file():
            raise SystemExit(f"missing normalized target: {target_path}")
        source_hash = digest(source_path)
        target_hash = digest(target_path)
        if source_hash != target_hash:
            raise SystemExit(f"content mismatch: {source_path} -> {target_path}")
        rows.append((str(source_path.relative_to(source)), str(target_path.relative_to(repository)), source_hash))

    source_map = repository / "SOURCE_FILE_MAP.tsv"
    source_map.write_text(
        "source_path\tnormalized_path\tsha256\n"
        + "".join(f"{old}\t{new}\t{sha}\n" for old, new, sha in rows),
        encoding="utf-8",
    )

    manifest = repository / "SHA256SUMS"
    files = [
        path for path in sorted(repository.rglob("*"))
        if path.is_file()
        and path != manifest
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    ]
    manifest.write_text(
        "".join(f"{digest(path)}  ./{path.relative_to(repository)}\n" for path in files),
        encoding="utf-8",
    )
    print(f"source_files={len(rows)}")
    print(f"manifest_files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
