from __future__ import annotations

import secrets


def int_to_bytes(x: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _nonzero_random_bytes(n: int) -> bytes:
    """Return n random bytes with no zero bytes."""
    out = bytearray()
    while len(out) < n:
        b = secrets.token_bytes(n - len(out))
        out.extend(x for x in b if x != 0)
    return bytes(out[:n])


def toy_pad(message: bytes, k: int) -> bytes:
    """Toy padding with an unambiguous delimiter.

    Format: 0x00 || 0x02 || PS || 0x00 || M
    - PS is random NON-ZERO bytes
    - k is the modulus length in bytes
    """
    if k < 11:
        raise ValueError("k too small for padding")
    if len(message) > k - 11:
        raise ValueError("message too long")

    ps_len = k - 3 - len(message)
    if ps_len < 8:
        raise ValueError("padding string too short")

    ps = _nonzero_random_bytes(ps_len)
    return b"\x00\x02" + ps + b"\x00" + message


def toy_unpad(padded: bytes) -> bytes:
    """Inverse of toy_pad()."""
    if len(padded) < 11:
        raise ValueError("invalid padding length")
    if padded[0] != 0 or padded[1] != 2:
        raise ValueError("invalid padding header")

    # Find the 0x00 separator after PS
    try:
        sep = padded.index(b"\x00", 2)
    except ValueError as e:
        raise ValueError("invalid padding (no separator)") from e

    ps = padded[2:sep]
    if len(ps) < 8:
        raise ValueError("invalid padding (PS too short)")
    if any(x == 0 for x in ps):
        raise ValueError("invalid padding (zero in PS)")

    return padded[sep + 1 :]
