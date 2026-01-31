from crypto_suite.utils.math import modexp, modinv


def test_modexp_matches_pow():
    assert modexp(3, 12345, 97) == pow(3, 12345, 97)


def test_modinv():
    inv = modinv(17, 3120)
    assert (17 * inv) % 3120 == 1
