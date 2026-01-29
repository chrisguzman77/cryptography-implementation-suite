from __future__ import annotations

from crypto_suite.utils.math import modexp


def brute_force_dlog(p: int, g: int, y: int, max_x: int | None = None) -> int | None:
    """Brute-force discrete log: find x such that g^x = y (mod p).
    Works only when p is small / weak.
    """
    limit = max_x if max_x is not None else p
    cur = 1
    for x in range(0, limit):
        if cur == y:
            return x
        cur = (cur * g) % p
    return None


def small_prime_dh_break(p: int, g: int, A: int, B: int) -> int | None:
    """Recover shared secret by solving discrete log for A=g^a and/or B=g^b when p is small."""
    a = brute_force_dlog(p, g, A)
    if a is None:
        return None
    return modexp(B, a, p)
