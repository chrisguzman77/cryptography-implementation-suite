from __future__ import annotations

from dataclasses import dataclass


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended GCD
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, n: int) -> int:
    """Modular inverse of a mod n.
    Raises ValueError if inverse doesn't exist.
    """
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % n


def modexp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation (pow(base, exp, mod) reimplemented for learning.)"""
    if mod <= 0:
        raise ValueError("mod must be positive")
    result = 1
    base %= mod
    e = exp
    while e > 0:
        if e & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        e >>= 1
    return result


@dataclass(frozen=True)
class ModPrimeField:
    """Tiny helper representing F_p for prime p (for ECC)."""

    p: int

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.p

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inv(self, a: int) -> int:
        return modinv(a, self.p)
