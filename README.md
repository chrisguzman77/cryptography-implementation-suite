# Cryptography Implementation Suite (Learning Project)

Implements:
- RSA (keygen, encrypt/decrypt, sign/verify) — **toy padding**
- Diffie–Hellman (finite-field DH)
- Simplified ECC (prime-field curve + scalar multiplication)
- Weak-parameter attack demonstrations

## Quickstart (Windows / PowerShell)

```powershell
uv sync --extra dev
uv run crypto-suite all
uv run pytest
uv run ruff check .
uv run ruff format .
