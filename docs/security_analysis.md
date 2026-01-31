# Security Analysis (Learning Suite)

This repository contains learning-oriented implementations of:
- RSA
- Finite-field Diffie-Hellman
- Simplified ECC over prime fields

## What makes parameters "weak"

### RSA 
**Weaknesses demonstrated**
- Small modulus (e.g., 512-bit): factorable with tools like Pollard Rho
- Small public exponent + no padding: can allow algebraic message recovery

**Production expectations**
- 2048-bit minimum today (often 3072+ for longer-term)
- OAEP for encryption, PSS for signatures
- Constant-time operations, hardened bignum arithmetic, side-channel mitigations

### Diffie-Hellman
**Weaknedded demonstrated**
- Small prime p: discrete log becomes brute-forceable

**Production expectations**
- Use standardized safe primes or modern groups
- Validate public keys, prevent small-subgroup confinement
- Prefer ECDH with modern curves in many applications

### ECC
**Weaknesses demonstrated**
- Small toy curves: ECDLP can be brute-forced

**Production expectations**
- Use vetted curves (e.g., NIST P-256, Curve25519) and validated implementations
- Constant-time scalar multiplication
- Strict point vcalidation and cofactor handling

## Takeaway
Security comes from:
1. Correct math + correct group/curve choices
2. Correct *protocol* choices (padding, validation, randomness)
3. Correct implementation hygeine (constant-time, side-channel resistence, testing)