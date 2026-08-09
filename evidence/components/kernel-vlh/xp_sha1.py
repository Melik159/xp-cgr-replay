#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

MASK32 = 0xFFFFFFFF

SHA1_IV = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)


def rol32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def fmt_words(words: Sequence[int]) -> str:
    return " ".join(f"{w:08x}" for w in words)


def fmt_hex_lines(buf: bytes, width: int = 16) -> str:
    rows: List[str] = []
    for i in range(0, len(buf), width):
        chunk = buf[i:i + width]
        rows.append(" ".join(f"{b:02x}" for b in chunk))
    return "\n".join(rows)


def words_to_bytes_be(words: Sequence[int]) -> bytes:
    return b"".join((w & MASK32).to_bytes(4, "big") for w in words)


def words_to_bytes_le(words: Sequence[int]) -> bytes:
    return b"".join((w & MASK32).to_bytes(4, "little") for w in words)


def bytes_to_words_be(block64: bytes) -> List[int]:
    if len(block64) != 64:
        raise ValueError("block must be 64 bytes")
    return [int.from_bytes(block64[i:i + 4], "big") for i in range(0, 64, 4)]


def bytes_to_words_le(block64: bytes) -> List[int]:
    if len(block64) != 64:
        raise ValueError("block must be 64 bytes")
    return [int.from_bytes(block64[i:i + 4], "little") for i in range(0, 64, 4)]


def sha1_compress_from_words(state: Sequence[int], w0_15: Sequence[int]) -> Tuple[int, int, int, int, int]:
    if len(state) != 5:
        raise ValueError("state must contain 5 words")
    if len(w0_15) != 16:
        raise ValueError("w0_15 must contain 16 words")

    w = list(w0_15)
    for t in range(16, 80):
        w.append(rol32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1))

    a, b, c, d, e = [x & MASK32 for x in state]
    h0, h1, h2, h3, h4 = a, b, c, d, e

    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif t < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (rol32(a, 5) + f + e + k + w[t]) & MASK32
        e = d
        d = c
        c = rol32(b, 30)
        b = a
        a = temp

    return (
        (h0 + a) & MASK32,
        (h1 + b) & MASK32,
        (h2 + c) & MASK32,
        (h3 + d) & MASK32,
        (h4 + e) & MASK32,
    )


def transform_std(state: Sequence[int], block64: bytes) -> Tuple[int, int, int, int, int]:
    return sha1_compress_from_words(state, bytes_to_words_be(block64))


def transform_ns(state: Sequence[int], block64: bytes) -> Tuple[int, int, int, int, int]:
    return sha1_compress_from_words(state, bytes_to_words_le(block64))


def sha1_pad_std(count_hi: int, count_lo: int, used: int) -> bytes:
    pad_len = 0x40 - used
    if pad_len <= 8:
        pad_len += 0x40

    pad = bytearray(pad_len)
    pad[0] = 0x80

    bit_hi = ((count_hi << 3) | (count_lo >> 29)) & MASK32
    bit_lo = (count_lo << 3) & MASK32

    pad[-8:-4] = bit_hi.to_bytes(4, "big")
    pad[-4:] = bit_lo.to_bytes(4, "big")
    return bytes(pad)


def sha1_pad_ns(count_hi: int, count_lo: int, used: int) -> bytes:
    pad_len = 0x40 - used
    if pad_len <= 8:
        pad_len += 0x40

    pad = bytearray(pad_len)
    pad[0] = 0x80

    len_dword_0 = ((count_hi << 3) | (count_lo >> 29)) & MASK32
    len_dword_1 = (count_lo << 3) & MASK32

    pad[-8:-4] = len_dword_0.to_bytes(4, "little")
    pad[-4:] = len_dword_1.to_bytes(4, "little")
    return bytes(pad)


@dataclass
class SHA1Context:
    state: Tuple[int, int, int, int, int] = SHA1_IV
    count_hi: int = 0
    count_lo: int = 0
    buffer: bytearray = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.buffer is None:
            self.buffer = bytearray(64)
        else:
            self.buffer = bytearray(self.buffer)
            if len(self.buffer) != 64:
                raise ValueError("buffer must be 64 bytes")

    def clone(self) -> "SHA1Context":
        return SHA1Context(
            state=tuple(self.state),
            count_hi=self.count_hi,
            count_lo=self.count_lo,
            buffer=bytearray(self.buffer),
        )

    @property
    def count_bytes(self) -> int:
        return ((self.count_hi & MASK32) << 32) | (self.count_lo & MASK32)


def _add_count(ctx: SHA1Context, nbytes: int) -> None:
    old_lo = ctx.count_lo
    ctx.count_lo = (ctx.count_lo + nbytes) & MASK32
    if ctx.count_lo < old_lo:
        ctx.count_hi = (ctx.count_hi + 1) & MASK32


def _update_generic(ctx: SHA1Context, data: bytes, transform_fn) -> None:
    if not data:
        return

    used = ctx.count_lo & 0x3F
    _add_count(ctx, len(data))

    i = 0

    if used != 0:
        take = min(64 - used, len(data))
        ctx.buffer[used:used + take] = data[:take]
        i += take
        used += take

        if used == 64:
            ctx.state = transform_fn(ctx.state, bytes(ctx.buffer))
            used = 0

    while i + 64 <= len(data):
        ctx.state = transform_fn(ctx.state, data[i:i + 64])
        i += 64

    if i < len(data):
        remain = len(data) - i
        ctx.buffer[0:remain] = data[i:]
        if remain < 64:
            ctx.buffer[remain:64] = b"\x00" * (64 - remain)


def update_std(ctx: SHA1Context, data: bytes) -> None:
    _update_generic(ctx, data, transform_std)


def update_ns(ctx: SHA1Context, data: bytes) -> None:
    _update_generic(ctx, data, transform_ns)


def final_std(ctx: SHA1Context) -> Tuple[Tuple[int, int, int, int, int], bytes, bytes]:
    used = ctx.count_lo & 0x3F
    pad = sha1_pad_std(ctx.count_hi, ctx.count_lo, used)

    work = ctx.clone()
    update_std(work, pad)
    digest = words_to_bytes_be(work.state)
    return work.state, pad, digest


def final_ns(ctx: SHA1Context) -> Tuple[Tuple[int, int, int, int, int], bytes, bytes]:
    used = ctx.count_lo & 0x3F
    pad = sha1_pad_ns(ctx.count_hi, ctx.count_lo, used)

    work = ctx.clone()
    update_std(work, pad)
    digest = words_to_bytes_le(work.state)
    return work.state, pad, digest


@dataclass(frozen=True)
class UpdateInput:
    name: str
    data: bytes


def make_updates(items: Sequence[Tuple[str, bytes]]) -> List[UpdateInput]:
    return [UpdateInput(name=name, data=data) for name, data in items]


class ReplayCase:
    def __init__(
        self,
        *,
        name: str,
        updates: Sequence[UpdateInput],
        mode: str = "sha1_std",
        initial_state: Sequence[int] = SHA1_IV,
        initial_count_hi: int = 0,
        initial_count_lo: int = 0,
        initial_buffer: bytes = b"\x00" * 64,
        observed_state_after_updates: Optional[Sequence[int]] = None,
        observed_count_after_updates: Optional[int] = None,
        observed_buffer_after_updates: Optional[bytes] = None,
        observed_digest: Optional[bytes] = None,
        notes: Optional[str] = None,
        **legacy_kwargs,
    ) -> None:
        self.observed_state_after_final_update = legacy_kwargs.pop(
            "observed_state_after_final_update", None
        )
        if legacy_kwargs:
            unknown = ", ".join(sorted(legacy_kwargs.keys()))
            raise TypeError(f"unexpected keyword argument(s): {unknown}")

        allowed_modes = {"sha1_std", "observed_trace", "ns_candidate"}
        if mode not in allowed_modes:
            raise ValueError(f"mode must be one of {sorted(allowed_modes)}")

        if len(initial_state) != 5:
            raise ValueError("initial_state must contain 5 words")
        if len(initial_buffer) != 64:
            raise ValueError("initial_buffer must be exactly 64 bytes")

        self.name = name
        self.mode = mode
        self.updates = list(updates)
        self.initial_state = tuple(int(x) & MASK32 for x in initial_state)
        self.initial_count_hi = int(initial_count_hi) & MASK32
        self.initial_count_lo = int(initial_count_lo) & MASK32
        self.initial_buffer = bytes(initial_buffer)
        self.observed_state_after_updates = (
            tuple(int(x) & MASK32 for x in observed_state_after_updates)
            if observed_state_after_updates is not None
            else None
        )
        self.observed_count_after_updates = (
            int(observed_count_after_updates)
            if observed_count_after_updates is not None
            else None
        )
        self.observed_buffer_after_updates = (
            bytes(observed_buffer_after_updates)
            if observed_buffer_after_updates is not None
            else None
        )
        self.observed_digest = bytes(observed_digest) if observed_digest is not None else None
        self.notes = notes
