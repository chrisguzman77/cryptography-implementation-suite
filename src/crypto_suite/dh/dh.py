from __future__ import annotations

import secrets

from crypto_suite.utils.math import modexp


def generate_private_key(q: int) -> int:
    """Private exponent in [2, q-2]. If q is prime order or (p-1), depends on group choice."""
    if q < 5:
        raise ValueError("q too small")
    return secrets.randbelow(q - 3) + 2


def public_key(p: int, g: int, a: int) -> int:
    return modexp(g, a, p)


def shared_secret(p: int, other_pub: int, a: int) -> int:
    return modexp(other_pub, a, p)
