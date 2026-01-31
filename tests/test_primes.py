from crypto_suite.utils.primes import is_probable_prime


def test_is_probable_prime_small():
    assert is_probable_prime(2)
    assert is_probable_prime(3)
    assert is_probable_prime(97)
    assert not is_probable_prime(1)
    assert not is_probable_prime(100)
