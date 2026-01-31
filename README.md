# Cryptography Implementation Suite

A learning-focused cryptography project implementing core public-key systems from scratch in Python, along with attack demonstrations and performance benchmarks.

This project emphasizes mathematical understanding, security intuition, and engineering discipline rather than relying on black-box crypto libraries.

---

## Educational Disclaimer

Do NOT use this code in production.

This repository is intentionally designed for:

- education

- experimentation

- security research

- portfolio demonstration

It lacks production protections such as:

- constant-time implementations

- hardened padding schemes (OAEP / PSS)

- side-channel resistance

- formally audited primitives

Always use vetted libraries like cryptography for real-world applications.

---

## Implemented Cryptosystems
### RSA (Rivest–Shamir–Adleman)

Features:

- Key generation using Miller–Rabin prime testing
- Encryption / Decryption
- Signature / Verification
- Toy padding implementation
- Weak-parameter attack demonstrations
- CRT-ready architecture

Concepts demonstrated:

- Modular exponentiation

- Euler’s Totient

- Prime generation

- Public vs private exponents

---

### Diffie–Hellman (Finite Field)

Features:

- Private/public key generation
- Shared secret derivation
- Discrete-log brute force attack demo
- Benchmarking

Concepts demonstrated:

- Cyclic groups

- Discrete logarithm hardness

- Key exchange without prior secrets

---

### Elliptic Curve Cryptography (Simplified)

Features:

- Curve arithmetic over prime fields
- Point addition & doubling
- Scalar multiplication (double-and-add)
- ECDLP brute-force demo on toy curves

Concepts demonstrated:

- Finite fields

- Elliptic curve group law

- Scalar multiplication

- Security-per-bit advantages

## Attack Demonstrations

This suite intentionally generates weak parameters to demonstrate why cryptographic best practices matter.

### RSA Factorization

Uses:

- Trial division

- Pollard Rho

A deliberately weak RSA modulus is constructed with an intentionally small prime factor so the attack completes deterministically.

### Low-Exponent RSA Attack

Shows how RSA without padding can leak plaintext when using small public exponents (e.g., e = 3).

### Discrete Log Attack

Brute-forces small DH groups to demonstrate why large primes are required.

---

## Benchmarks

The project includes a benchmarking framework comparing cryptographic operations such as:

- RSA key generation

- DH public key computation

- DH shared secret derivation

- ECC scalar multiplication

Example output:

| Primitive	| Avg Time	| Notes
|-----------|-----------|-------|
RSA Keygen	| Slow	| Expected due to prime generation
DH Public	| Fast	| Single modular exponentiation
DH Shared	| Fast	| Same complexity as public
ECC Scalar Mult	| Very Fast	| Smaller operands

(Actual timings vary by CPU.)
---

## Mathematical Foundations

This project directly applies:

- Modular arithmetic
- Prime number theory
- Groups & finite fields
- Discrete logarithms
- Elliptic curve algebra

It is designed to bridge the gap between abstract cryptography and real implementations.

---

## Project Architecture

Uses a professional src layout:
```
src/
   crypto_suite/
      rsa/
      dh/
      ecc/
      utils/
      benchmarks/
tests/
```

Tooling:

- uv — reproducible Python environments

- Ruff — linting & formatting

- pytest — automated tests

- GitHub Actions — CI ready

---

## Getting Started

Install dependencies
```
uv sync --extra dev
```
Run the demo suite
```
uv run crypto-suite all
```
Run attacks only
```
uv run crypto-suite rsa-attacks
```
Run tests
```
uv run pytest
```
Lint the project
```
uv run ruff check .
uv run ruff format .
```

---

##Demo Modes

The project separates RSA into two modes:

### Realistic Demo Mode

Used for encryption/signature demonstrations.

Key sizes:

- 1024-bit (fast demo)

- 2048-bit (realistic)

### Attack Demo Mode

Generates intentionally weak RSA keys that are guaranteed to be factorable quickly for educational purposes.

---

## Why This Project Exists

Most developers use crypto libraries without understanding the underlying mechanics.

This project was built to deeply understand:

- why cryptosystems are secure

- how they fail

- what parameters matter

- how performance scales

It reflects the mindset required for security engineering rather than just application development.
