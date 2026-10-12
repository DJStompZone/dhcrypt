# dhcrypt

Production-ready, OpenSSL-interoperable Finite-Field Diffie-Hellman (FFDH) key exchange and AES-256-GCM authenticated encryption in Python.

[![Test Suite](https://img.shields.io/badge/coverage-100%25-brightgreen)](tests)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

`dhcrypt` provides an end-to-end cryptographic toolkit for Diffie-Hellman parameter generation, key generation, key agreement, and symmetric authenticated encryption. It is engineered from the ground up for strict OpenSSL compatibility (`openssl genpkey -paramfile`, `openssl pkeyutl -derive`) while adhering to **SOLID** architectural design, **DRY** principles, and complete test verification (100% line coverage).

---

## Architectural Principles (SOLID & DRY)

- **Single Responsibility Principle (SRP)**:
  - `dhcrypt.models`: Domain dataclasses representing cryptographic parameters (`DHParams`).
  - `dhcrypt.math`: Mathematical primitives including Miller-Rabin probabilistic primality checks, subgroup safety validation, and exponent generation.
  - `dhcrypt.serialization`: ASN.1 DER and PKCS#3/PKCS#8/SPKI PEM encoders and decoders.
  - `dhcrypt.symmetric`: HKDF key derivation and AES-256-GCM AEAD encryption/decryption.
  - `dhcrypt.dh`: Diffie-Hellman protocol operations (group parameter generation, private key creation, shared secret computation).
  - `dhcrypt.io`: Secure filesystem and standard stream I/O utilities enforcing 0600 file permissions for sensitive private keys.
  - `dhcrypt.service`: Application service facade orchestrating end-to-end workflows.
  - `dhcrypt.cli`: Argument parsing, flag validation, and error reporting.

- **Open/Closed Principle (OCP)**:
  - Pluggable `SymmetricCipher` protocol allows injecting alternative symmetric authenticated ciphers while defaulting to standard `AESGCMSymmetricCipher`.
  - Configurable KDF salt, context info, and key length.

- **Liskov Substitution Principle (LSP)**:
  - Granular exception hierarchy (`DHParameterError`, `DHKeyError`, `DHValidationError`, `DHCryptoError`, `DHIOError`) all inherit from base `DHError`.

- **Interface Segregation Principle (ISP)**:
  - Core mathematical, serialization, and cryptographic functions accept in-memory buffers (`bytes`, `int`), decoupling domain logic from filesystem operations or CLI structures.

- **Dependency Inversion Principle (DIP)**:
  - High-level services and CLI commands depend on pure abstractions and data models rather than concrete filesystem implementations.

---

## Installation

### Using Poetry

```bash
poetry install
```

### Using pip

```bash
pip install .
```

---

## Command-Line Interface (CLI)

The `dhcrypt` command-line executable supports five core operations:

```
usage: dhcrypt [-h] {genparams,keygen,derive,encrypt,decrypt} ...
```

### 1. Parameter Generation (`genparams`)

Generate safe-prime Diffie-Hellman parameters serialized in PKCS#3 PEM format.

```bash
dhcrypt genparams --bits 2048 -o dhp.pem
```

- `--bits`: Bit length of the prime modulus (default: 2048).
- `-o`, `--out`: Output destination path (`-` for stdout, default: `-`).

### 2. Keypair Generation (`keygen`)

Generate a private key (PKCS#8 format, mode 0600) and public key (SPKI format) from group parameters.

```bash
dhcrypt keygen -p dhp.pem --priv me.pem --pub me.pub.pem
```

- `-p`, `--params`: Path to DH parameters PEM (or any DH key PEM carrying parameters).
- `--priv`: Destination path for the unencrypted private key (mode 0600).
- `--pub`: Destination path for the public key.
- `--private-length`: Optional private exponent bit length (e.g., 256 for short exponent).
- `--force`: Overwrite existing private key file if it already exists.

### 3. Key Agreement (`derive`)

Derive the raw shared secret between our private key and a peer's public key.

```bash
dhcrypt derive --priv me.pem --peer them.pub.pem --fingerprint -o secret.bin
```

- `--priv`: Path to our private key PEM.
- `--peer`: Path to peer's public key PEM.
- `-o`, `--out`: Output destination (`-` for stdout).
- `--hex`: Encode secret as hexadecimal text.
- `--fingerprint`: Output SHA-256 fingerprint of the shared secret to stderr for out-of-band verification.
- `--strip-zeros`: Strip leading zero bytes (reproduces legacy OpenSSL 1.x / `DH_compute_key` behavior).

### 4. Authenticated Encryption (`encrypt`)

Encrypt a payload using AES-256-GCM with a key derived from either the shared secret file or direct peer keys via HKDF-SHA256.

```bash
# Using derived secret file:
dhcrypt encrypt -k secret.bin -p plaintext.txt -o message.bin

# Or deriving directly from keys:
dhcrypt encrypt --priv me.pem --peer them.pub.pem -p plaintext.txt -o message.bin
```

- `-k`, `--pem`: Path to file containing the shared secret (raw bytes or hex string).
- `--priv` and `--peer`: Derive secret directly using our private key and peer's public key.
- `-p`, `--payload`: Path to input plaintext (`-` for stdin).
- `-o`, `--out`: Path to output ciphertext (`-` for stdout).

### 5. Authenticated Decryption (`decrypt`)

Verify the AES-256-GCM authentication tag and decrypt the ciphertext payload.

```bash
# Using derived secret file:
dhcrypt decrypt -k secret.bin -p message.bin -o recovered.txt

# Or deriving directly from keys:
dhcrypt decrypt --priv me.pem --peer them.pub.pem -p message.bin -o recovered.txt
```

---

## Python API Usage

`dhcrypt` can be imported and used directly as a Python library:

```python
from dhcrypt import (
    generate_parameters_pem,
    generate_keypair_pem,
    derive_shared_secret,
    encrypt_message,
    decrypt_message,
)

# 1. Generate DH group parameters
params_pem = generate_parameters_pem(key_size=2048)

# 2. Alice generates keypair
alice_priv, alice_pub, alice_bits = generate_keypair_pem(params_pem)

# 3. Bob generates keypair
bob_priv, bob_pub, bob_bits = generate_keypair_pem(params_pem)

# 4. Compute shared secret
alice_secret = derive_shared_secret(alice_priv, bob_pub)
bob_secret = derive_shared_secret(bob_priv, alice_pub)
assert alice_secret == bob_secret

# 5. Encrypt and decrypt messages
plaintext = b"Confidential payload transmission."
ciphertext = encrypt_message(alice_secret, plaintext)

decrypted = decrypt_message(bob_secret, ciphertext)
assert decrypted == plaintext
```

### Low-Level Primitives

```python
from dhcrypt import (
    DHParams,
    compute_shared_secret,
    derive_symmetric_key,
    encrypt_payload,
    decrypt_payload,
    validate_peer_public,
)

# Custom parameter validation and key agreement
params = DHParams(p=0xFFFFFFFFFFFFFFFF, g=2)
validate_peer_public(peer_public_int, params)
shared_bytes = compute_shared_secret(private_int, peer_public_int, params)

# HKDF key derivation & AES-GCM
key = derive_symmetric_key(shared_bytes, salt=b"optional-salt", info=b"app-context")
encrypted = encrypt_payload(key, b"data")
decrypted = decrypt_payload(key, encrypted)
```

---

## Security & Wire Format Specifications

- **Wire Format**:
  Ciphertext payloads output by `encrypt` use the format:
  $$\text{Payload} = \text{Nonce}_{12\text{ bytes}} \parallel \text{Ciphertext} \parallel \text{Tag}_{16\text{ bytes}}$$
- **Key Derivation**:
  Shared secrets derived from Diffie-Hellman exchange are passed through HKDF-SHA256 (`info=b"stompzone-dh-kex-context"`) to derive a 256-bit symmetric encryption key.
- **Subgroup Validation**:
  Peer public values are strictly validated against $[2, p - 2]$. For safe-prime groups where generator $g$ generates an order-$q$ subgroup, $y^q \equiv 1 \pmod p$ is enforced to prevent small-subgroup confinement attacks.
- **OpenSSL Interoperability**:
  Handles PKCS#3 ASN.1 structures with optional `privateValueLength` parameter attributes that cause errors in naive OpenSSL/cryptography integrations.

---

## Testing & Quality Assurance

Run the test suite with coverage reporting:

```bash
poetry run pytest --cov=dhcrypt --cov-report=term-missing
```

### Test Coverage Summary

```
Name                       Stmts   Miss  Cover
----------------------------------------------
dhcrypt\__init__.py           14      0   100%
dhcrypt\__main__.py            4      0   100%
dhcrypt\cli.py                90      0   100%
dhcrypt\constants.py           6      0   100%
dhcrypt\dh.py                 33      0   100%
dhcrypt\exceptions.py          6      0   100%
dhcrypt\io.py                 45      0   100%
dhcrypt\math.py               52      0   100%
dhcrypt\models.py             18      0   100%
dhcrypt\serialization.py      97      0   100%
dhcrypt\service.py            27      0   100%
dhcrypt\symmetric.py          44      0   100%
----------------------------------------------
TOTAL                        436      0   100%
```

---

## License

MIT License. Copyright (c) 2026 DJ Stomp.
