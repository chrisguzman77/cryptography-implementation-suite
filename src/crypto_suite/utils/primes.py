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


def pollard_rho(n: int) -> int | None:
    """Very small Pollard Rho factor finder. Returns a non-trivial factor or None."""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    if n < 2:
        return None

    def f(x: int, c: int) -> int:
        return (x * x + c) % n

    for _attempt in range(10):
        x = secrets.randbelow(n - 2) + 2
        y = x
        c = secrets.randbelow(n - 1) + 1
        d = 1
        while d == 1:
            x = f(x, c)
            y = f(f(y, c), c)
            d = gcd(abs(x - y), n)
        if d != n:
            return d
    return None


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)
