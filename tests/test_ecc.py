from crypto_suite.ecc.ecc import Curve, Point, scalar_mult


def test_ecc_ecdh_style():
    curve = Curve(p=9739, a=497, b=1768)
    G = Point(1804, 5368)
    a = 1337
    b = 4242
    A = scalar_mult(curve, a, G)
    B = scalar_mult(curve, b, G)
    assert scalar_mult(curve, a, B) == scalar_mult(curve, b, A)
