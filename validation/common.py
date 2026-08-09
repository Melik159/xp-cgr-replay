from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


class ValidationError(RuntimeError):
    """Raised when retained evidence does not satisfy a claimed relation."""


@dataclass(frozen=True)
class Outcome:
    name: str
    detail: str
    status: str = "PASS"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    allowed_codes: Iterable[int] = (0,),
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        list(command),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if proc.returncode not in set(allowed_codes):
        tail = "\n".join(proc.stdout.splitlines()[-20:])
        raise ValidationError(
            f"command failed with exit {proc.returncode}: {' '.join(command)}\n{tail}"
        )
    return proc


def require_text(text: str, marker: str) -> None:
    require(marker in text, f"missing expected marker: {marker}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"invalid JSONL {path}:{number}: {exc}") from exc
    return rows


def rc4_ksa(key: bytes) -> bytes:
    require(bool(key), "RC4 KSA key is empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return bytes(state)


def rc4_xor(state_sij: bytes, data: bytes) -> tuple[bytes, bytes]:
    require(len(state_sij) >= 258, "RC4 state is shorter than S+i+j")
    state = list(state_sij[:256])
    i = state_sij[256]
    j = state_sij[257]
    output = bytearray()
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output), bytes(state) + bytes((i, j))

