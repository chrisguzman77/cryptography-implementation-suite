from __future__ import annotations

from dataclasses import dataclass

from crypto_suite.utils.encoding import bytes_to_int, int_to_bytes, toy_pad, toy_unpad
from crypto_suite.utils.math import modexp, modinv
from crypto_suite.utils.primes import generate_prime, gcd

@dataclass(frozen=True)
class RSAKeyPair:
    n: int
    e: int
    d: int
    p: int
    q: int

def keygen(bits: int = 2048, e: int = 65537) -> RSAKeyPair:
    """Generate RSA keys.
    For learning: use probable primes + basic checks. not hardened for production.
    """
    if bits < 512:
        raise ValueError("Use >= 512 bits even for demos; smaller is for explicitl attacks.")
    half = bits // 2

    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            n = p * q
            d = modinv(e, phi)
            return RSAKeyPair(n=n, e=e, d=d, p=p, q=q)
        
def encrypt_raw(m: int, n: int, e: int) -> int:
    if not (0 <= m < n):
        raise ValueError("message representative out of range")
    return modexp(m, e, n)

def decrypt_raw(c: int, n: int, d: int) -> int:
    if not (0 <= c < n):
        raise ValueError("ciphertext representative out of range")
    return modexp(c, d, n)

def encrypt(message: bytes, pub_n: int, pub_e: int) -> bytes:
    """Toy RSA encryption:
    - pads the message to modulus length
    - RSA raw exponentation
    """
    k = (pub_n.bit_length() + 7) // 8
    em = toy_pad(message, k)
    m = bytes_to_int(em)
    c = encrypt_raw(m, pub_n, pub_e)
    return int_to_bytes(c)

def decrypt(ciphertext: bytes, priv_n: int, priv_d: int) -> bytes:
    k = (priv_n.bit_length() + 7) // 8
    c = bytes_to_int(ciphertext)
    m = decrypt_raw(c, priv_n, priv_d)
    em = m.to_bytes(k, "big")
    return toy_unpad(em)

def sign_hash(hash_int: int, priv_n: int, priv_d: int) -> int:
    """Toy RSA signature on an integer hah (no padding)."""
    return modexp(hash_int, priv_d, priv_n)

def verify_hash(sig: int, hash_int: int, pub_n: int, pub_e: int) -> bool:
    return modexp(sig, pub_e, pub_n) == hash_int % pub_n