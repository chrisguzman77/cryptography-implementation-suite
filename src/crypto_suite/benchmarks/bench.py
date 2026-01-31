from __future__ import annotations

import time
from dataclasses import dataclass

from crypto_suite.dh.dh import generate_private_key, public_key, shared_secret
from crypto_suite.ecc.ecc import Curve, Point, scalar_mult
from crypto_suite.rsa.rsa import keygen


@dataclass(frozen=True)
class BenchResult:
    name: str
    seconds: float
    notes: str


def _timeit(fn, iters: int = 200) -> float:
    t0 = time.perf_counter()
    for _ in range(iters):
        fn()
    t1 = time.perf_counter()
    return (t1 - t0) / iters


def bench_all() -> list[BenchResult]:
    results: list[BenchResult] = []

    # RSA keygen is expensive; do fewer iters
    def rsa_keygen_1024():
        keygen(bits=1024)

    t = _timeit(rsa_keygen_1024, iters=5)
    results.append(BenchResult("RSA keygen 1024-bit", t, "Toy still slow vs others"))

    # DH ops
    p = 2147483647
    g = 5
    a = generate_private_key(p - 1)
    b = generate_private_key(p - 1)
    A = public_key(p, g, a)
    B = public_key(p, g, b)

    # Benchmark public key generation
    t_pub = _timeit(lambda: public_key(p, g, a), iters=5000)
    results.append(BenchResult("DH public key", t_pub, "g^a mod p"))

    # Benchmark shared secret (Alice side)
    t_shared_a = _timeit(lambda: shared_secret(p, B, a), iters=5000)
    results.append(BenchResult("DH shared (Alice)", t_shared_a, "B^a mod p"))

    # Benchmark shared secret (Bob side)
    t_shared_b = _timeit(lambda: shared_secret(p, A, b), iters=5000)
    results.append(BenchResult("DH shared (Bob)", t_shared_b, "A^b mod p"))

    # ECC scalar mult (toy)
    curve = Curve(p=9739, a=497, b=1768)
    G = Point(1804, 5368)
    tE = _timeit(lambda: scalar_mult(curve, 1337, G), iters=2000)
    results.append(BenchResult("ECC scalar_mult (toy)", tE, "Double-and-add, not optimized"))

    return results
