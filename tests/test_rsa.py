import hashlib

from crypto_suite.rsa.rsa import decrypt, encrypt, keygen, sign_hash, verify_hash


def test_rsa_roundtrip():
    kp = keygen(bits=1024)
    msg = b"test message"
    ct = encrypt(msg, kp.n, kp.e)
    pt = decrypt(ct, kp.n, kp.d)
    assert pt == msg


def test_rsa_sign_verify():
    kp = keygen(bits=1024)
    msg = b"sign me"
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    sig = sign_hash(h, kp.n, kp.d)
    assert verify_hash(sig, h, kp.n, kp.e)
