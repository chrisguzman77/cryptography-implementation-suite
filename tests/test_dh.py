from crypto_suite.dh.dh import generate_private_key, public_key, shared_secret


def test_dh_shared_secret():
    p = 2147483647
    g = 5
    a = generate_private_key(p - 1)
    b = generate_private_key(p - 1)
    A = public_key(p, g, a)
    B = public_key(p, g, b)
    assert shared_secret(p, B, a) == shared_secret(p, A, b)
