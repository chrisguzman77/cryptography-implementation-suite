from __future__ import annotations

import secrets

from crypto_suite.utils.math import modexp


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin primality test.
    - Deterministic for small n with certain bases, but we use randomized bases for learning.
    - round=32 is fine for demo sizes; for real cryptography sizes you'd do more carefule choices.
    """
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # write n-1 = d * 2^s with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = modexp(a, d, n)
        if x in (1, n - 1):
            continue
        witness = True
        for _r in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                witness = False
                break
        if witness:
            return False
    return True


def random_odd_int(bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be >= 2")
    n = secrets.randbits(bits)
    n |= 1
    n |= 1 << (bits - 1)  # ensure top bit set
    return n


def generate_prime(bits: int) -> int:
    """Generate a probable prime of size 'bits'."""
    while True:
        cand = random_odd_int(bits)
        if is_probable_prime(cand):
            return cand


def trial_division(n: int, limit: int = 100_000) -> int | None:
    """Try small primes up to 'limit' to find a factor quickly."""
    if n % 2 == 0:
        return 2
    f = 3
    while f * f <= n and f <= limit:
        if n % f == 0:
            return f
        f += 2
    return None


def pollard_rho(n: int, max_steps: int = 200_000, attempts: int = 20) -> int | None:
    """Pollard Rho factor finder with iteration caps to avoid hanging.
    Returns a non-trivial factor or None if not found quickly.
    """

    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    if n < 2:
        return None
    small = trial_division(n, limit=50_000)
    if small is not None and small not in (1, n):
        return small

    def f(x: int, c: int) -> int:
        return (x * x + c) % n

    for _attempt in range(attempts):
        x = secrets.randbelow(n - 2) + 2
        y = x
        c = secrets.randbelow(n - 1) + 1
        d = 1

        for step in range(max_steps):
            # If we haven't made progress in a while, restart this attempt
            if step > 0 and step % 100_000 == 0:
                break

            x = f(x, c)
            y = f(f(y, c), c)
            d = gcd(abs(x - y), n)

            if d == n:
                # failure for this attempt; restart with new parameters
                break
            if d > 1:
                return d

    return None


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)
