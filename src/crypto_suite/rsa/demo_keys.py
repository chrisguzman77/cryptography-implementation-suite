from __future__ import annotations

from crypto_suite.rsa.rsa import RSAKeyPair, keygen, keypair_from_primes
from crypto_suite.utils.primes import generate_prime


def generate_realistic_demo_rsa(bits: int = 1024) -> RSAKeyPair:
    """Normal demo keys (encrypt/decrypt/sign)."""
    if bits not in (1024, 2048):
        raise ValueError("Use 1024 (fast demo) or 2048 (realistic demo).")
    return keygen(bits=bits)


def generate_factorable_rsa(bits: int = 256) -> RSAKeyPair:
    """Deliberately weak RSA key meant to be factorable instantly.

    Strategy: choose a very small prime p (< 50,000) so trial division finds it immediately.
    Pair with a ~240-bit prime q so n is ~256 bits.

    This is intentionally insecure and designed for deterministic demos/tests.
    """
    if bits != 256:
        raise ValueError("This demo generator is tuned for 256-bit n.")

    # Small prime (must be < 50,000 so trial_division finds it)
    # We also need gcd(e, phi) == 1; easiest is: regenerate q if needed.
    p = 49999  # 49999 is prime and < 50,000

    # q sized so that n is ~256 bits
    q_bits = 240
    while True:
        q = generate_prime(q_bits)
        try:
            return keypair_from_primes(p, q)
        except ValueError:
            # rare case: e not coprime with phi; try another q
            continue
