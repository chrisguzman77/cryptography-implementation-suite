from crypto_suite.rsa.attacks import factor_if_weak
from crypto_suite.rsa.demo_keys import generate_factorable_rsa, generate_realistic_demo_rsa


def test_realistic_demo_key_sizes():
    assert generate_realistic_demo_rsa(1024).n.bit_length() >= 1022
    assert generate_realistic_demo_rsa(2048).n.bit_length() >= 2046


def test_factorable_key_can_be_factored_quickly():
    kp = generate_factorable_rsa(256)

    factors = None
    for _ in range(8):
        factors = factor_if_weak(kp.n, time_limit_s=6.0)
        if factors is not None:
            break

    assert factors is not None
