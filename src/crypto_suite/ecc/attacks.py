from __future__ import annotations

from crypto_suite.ecc.ecc import Curve, Point, scalar_mult


def brute_force_ecdlp(curve: Curve, G: Point, Q: Point, max_k: int) -> int | None:
    """Solve Q = kG by brute force (only works on tiny toy curves)."""
    for k in range(0, max_k + 1):
        if scalar_mult(curve, k, G) == Q:
            return k
    return None
