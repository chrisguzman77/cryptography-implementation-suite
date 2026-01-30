from __future__ import annotations

import argparse
import hashlib
import time

from crypto_suite.dh.attacks import small_prime_dh_break
from crypto_suite.dh.dh import generate_private_key, public_key, shared_secret
from crypto_suite.ecc.attacks import brute_force_ecdlp
from crypto_suite.ecc.ecc import Curve, Point, scalar_mult
from crypto_suite.rsa.attacks import factor_if_weak, low_exponent_no_padding_attack
from crypto_suite.rsa.demo_keys import generate_factorable_rsa, generate_realistic_demo_rsa
from crypto_suite.rsa.rsa import decrypt, encrypt, sign_hash, verify_hash


def demo_rsa():
    print("\n=== RSA Demo ===")
    kp = generate_realistic_demo_rsa(bits=1024)  # 1024 is not modern-secure, but OK for fast demos
    msg = b"hello rsa"
    ct = encrypt(msg, kp.n, kp.e)
    pt = decrypt(ct, kp.n, kp.d)
    print("Message:", msg)
    print("Decrypted:", pt)

    h = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    sig = sign_hash(h, kp.n, kp.d)
    ok = verify_hash(sig, h, kp.n, kp.e)
    print("Signature verifies:", ok)


def demo_rsa_attacks():
    print("\n=== RSA Weak Parameter Attacks ===")

    # 1) Factor small modulus
    print("Attempting to factor a deliberately weak RSA modulus...")
    weak = generate_factorable_rsa(bits=256)

    factors = factor_if_weak(weak.n, time_limit_s=3.0)
    print("Weak RSA n bits:", weak.n.bit_length())

    if factors is not None:
        p, q = factors
        print("✔ Factorization succeeded — modulus is insecure.")
        print("Recovered factors:")
        print("p =", p)
        print("q =", q)
    else:
        print("✔ Factorization did not finish quickly — modulus is stronger (or time-capped).")

    # 2) Low exponent / no padding (contrived)
    e = 3
    m = 42
    c = m**e  # no mod wrap at all (very contrived)
    recovered = low_exponent_no_padding_attack(c, e)
    print("Low-exponent no-padding recovered:", recovered)


def demo_dh():
    print("\n=== Diffie–Hellman Demo ===")
    # Small safe-ish demo prime (still tiny)
    p = 2147483647  # 2^31-1 Mersenne prime (demo only)
    g = 5
    a = generate_private_key(p - 1)
    b = generate_private_key(p - 1)
    A = public_key(p, g, a)
    B = public_key(p, g, b)
    s1 = shared_secret(p, B, a)
    s2 = shared_secret(p, A, b)
    print("Shared secrets match:", s1 == s2)


def demo_dh_attack():
    print("\n=== DH Attack: small p brute force ===")
    p = 467  # tiny prime -> breakable
    g = 2
    a = 123
    b = 77
    A = pow(g, a, p)
    B = pow(g, b, p)
    recovered = small_prime_dh_break(p, g, A, B)
    print("Recovered shared secret:", recovered)
    print("Actual shared secret:", pow(g, a * b, p))


def demo_ecc():
    print("\n=== ECC (Simplified) Demo ===")
    # A tiny toy curve (NOT secure)
    curve = Curve(p=9739, a=497, b=1768)
    G = Point(1804, 5368)
    assert curve.is_on_curve(G)

    a = 1337
    b = 4242
    A = scalar_mult(curve, a, G)
    B = scalar_mult(curve, b, G)
    s1 = scalar_mult(curve, a, B)
    s2 = scalar_mult(curve, b, A)
    print("ECDH-style shared point match:", s1 == s2)


def demo_ecc_attack():
    print("\n=== ECC Attack: tiny curve brute force ECDLP ===")
    curve = Curve(p=9739, a=497, b=1768)
    G = Point(1804, 5368)
    k = 1337
    Q = scalar_mult(curve, k, G)
    recovered = brute_force_ecdlp(curve, G, Q, max_k=5000)
    print("Recovered k:", recovered, "(actual:", k, ")")


def main():
    parser = argparse.ArgumentParser(prog="crypto-suite")
    parser.add_argument(
        "command",
        choices=["rsa", "rsa-attacks", "dh", "dh-attacks", "ecc", "ecc-attacks", "all"],
    )
    args = parser.parse_args()

    start = time.perf_counter()
    if args.command in ("rsa", "all"):
        demo_rsa()
    if args.command in ("rsa-attacks", "all"):
        demo_rsa_attacks()
    if args.command in ("dh", "all"):
        demo_dh()
    if args.command in ("dh-attacks", "all"):
        demo_dh_attack()
    if args.command in ("ecc", "all"):
        demo_ecc()
    if args.command in ("ecc-attacks", "all"):
        demo_ecc_attack()
    end = time.perf_counter()
    print(f"\nTotal demo time: {end - start:.3f}s")
