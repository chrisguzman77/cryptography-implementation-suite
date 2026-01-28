from __future__ import annotations

import math

from crypto_suite.utils.primes import pollard_rho

def factor_if_weak(n: int) -> tuple[int, int] | None:
    """Attempt to factor n using Pollard Rho (works if n is too small / weak)"""
    f = pollard_rho(n)
    if not f or f == 1 or f == n:
        return None
    return (f, n // f)

def low_exponent_no_padding_attack(c: int, e: int) -> int | None:
    """If RSA uses small e (e=3) and NO padding, and message is small:
    c = m^e (over integers, not wrapping mod n) => m = integer_root(c, e).
    Returns recovered m if exact.
    """
    if e <= 1:
        return None
    m = int(round(c ** (1 / e)))
    # verify by power (integer exact check)
    if m ** e == c:
        return m
    # safer integer root via binary search
    lo, hi = 0, 1
    while hi ** e < c:
        hi *= 2
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** e <= c:
            lo = mid
        else:
            hi = mid
    if lo ** e == c:
        return lo
    return None