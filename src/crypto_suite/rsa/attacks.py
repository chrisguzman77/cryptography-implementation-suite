from __future__ import annotations

import time

from crypto_suite.utils.primes import pollard_rho


def factor_if_weak(n: int, *, time_limit_s: float = 3.0) -> tuple[int, int] | None:
    """Attempt to factor n quickly (hard time limit).

    Important: Pollard Rho can take unpredictable time, so we run many small bursts
    rather than one huge call, so the wall-clock time stays bounded.
    """
    start = time.perf_counter()

    while (time.perf_counter() - start) < time_limit_s:
        # Small burst: ensures each call returns quickly.
        f = pollard_rho(n, max_steps=20_000, attempts=5)
        if f and f not in (1, n):
            return (f, n // f)

    return None


def low_exponent_no_padding_attack(c: int, e: int) -> int | None:
    """Low-exponent (e=3) + NO padding demo attack.
    If c = m^e as integers (no mod wrap), recover m via integer root.
    """
    if e <= 1:
        return None

    # integer e-th root by binary search
    lo, hi = 0, 1
    while hi**e < c:
        hi *= 2

    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**e <= c:
            lo = mid
        else:
            hi = mid

    return lo if lo**e == c else None
