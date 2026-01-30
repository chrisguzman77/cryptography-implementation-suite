from __future__ import annotations

from dataclasses import dataclass

from crypto_suite.utils.math import ModPrimeField


@dataclass(frozen=True)
class Curve:
    """Short Weierstrass curve: y^2 = x^3 + ax + b over F_p."""

    p: int
    a: int
    b: int

    def field(self) -> ModPrimeField:
        return ModPrimeField(self.p)

    def is_on_curve(self, P: Point) -> bool:
        if P.is_infinity:
            return True
        x, y = P.x, P.y
        f = self.field()
        left = f.mul(y, y)
        right = (x * x * x + self.a * x + self.b) % self.p
        return left == right


@dataclass(frozen=True)
class Point:
    x: int = 0
    y: int = 0
    is_infinity: bool = False


def point_neg(curve: Curve, P: Point) -> Point:
    if P.is_infinity:
        return P
    return Point(P.x, (-P.y) % curve.p)


def point_add(curve: Curve, P: Point, Q: Point) -> Point:
    """Elliptic curve group law over prime field (simplified, not constant-time)."""
    f = curve.field()

    if P.is_infinity:
        return Q
    if Q.is_infinity:
        return P

    if P.x == Q.x and (P.y != Q.y or P.y == 0):
        return Point(is_infinity=True)

    if P.x == Q.x and P.y == Q.y:
        # slope = (3x^2 + a) / (2y)
        num = (3 * P.x * P.x + curve.a) % curve.p
        den = (2 * P.y) % curve.p
        lam = f.mul(num, f.inv(den))
    else:
        # slope = (y2 - y1) / (x2 - x1)
        num = f.sub(Q.y, P.y)
        den = f.sub(Q.x, P.x)
        lam = f.mul(num, f.inv(den))

    x3 = (lam * lam - P.x - Q.x) % curve.p
    y3 = (lam * (P.x - x3) - P.y) % curve.p
    return Point(x3, y3)


def scalar_mult(curve: Curve, k: int, P: Point) -> Point:
    """Double-and-add scalar multiplication."""
    if k < 0:
        return scalar_mult(curve, -k, point_neg(curve, P))
    result = Point(is_infinity=True)
    addend = P
    n = k
    while n > 0:
        if n & 1:
            result = point_add(curve, result, addend)
        addend = point_add(curve, addend, addend)
        n >>= 1
    return result
