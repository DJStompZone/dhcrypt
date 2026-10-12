# dhcrypt

OpenSSL-interoperable Finite-Field Diffie-Hellman (FFDH) key exchange and AES-256-GCM authenticated encryption in Python.

[![PyPI version](https://img.shields.io/badge/pypi-v1.0.0-blue.svg?logo=pypi&logoColor=white)](https://pypi.org/project/dhcrypt/)
[![Python Versions](https://img.shields.io/badge/python-3.13%20%7C%203.14-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-52%20passed-brightgreen.svg?logo=pytest&logoColor=white)](tests)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg?logo=codecov&logoColor=white)](htmlcov/index.html)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Type Checking: Pyright](https://img.shields.io/badge/types-pyright-4B32C3.svg)](https://github.com/microsoft/pyright)
[![OpenSSL Compatible](https://img.shields.io/badge/OpenSSL-interoperable-721412.svg?logo=openssl&logoColor=white)](https://www.openssl.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Features

- **OpenSSL Interoperability**: Seamlessly exchanges keys with `openssl genpkey -paramfile`, `openssl pkeyutl -derive`, and standard OpenSSL 3.x / legacy 1.x workflows.
- **PKCS#3 ASN.1 Engine**: Built-in parser that correctly handles optional `privateValueLength` fields from `openssl genpkey -genparam`.
- **Authenticated Encryption**: AES-256-GCM authenticated cipher preventing unauthorized tampering and ciphertext manipulation.
- **Robust Key Derivation**: HKDF-SHA256 context-bound symmetric key derivation.
- **Active Subgroup Protection**: Miller-Rabin safe-prime subgroup checks ($y^q \equiv 1 \pmod p$) guarding against small-subgroup confinement attacks.
- **Secure File Permissions**: Enforces restrictive `0600` POSIX file permissions for private keys by default.
- **Zero-Dependency CLI & Library**: Run directly as a CLI tool or import into any Python project.

---

## Installation

### Using pip

```bash
pip install dhcrypt
```

### Using Poetry

```bash
poetry add dhcrypt
```

---

## Quick Start (CLI)

Perform a complete Diffie-Hellman key exchange and encrypted communication in five commands:

```bash
# 1. Generate DH group parameters
dhcrypt genparams --bits 2048 -o dhp.pem

# 2. Alice and Bob generate keypairs
dhcrypt keygen -p dhp.pem --priv alice.key --pub alice.pub
dhcrypt keygen -p dhp.pem --priv bob.key --pub bob.pub

# 3. Derive shared secret (or encrypt directly using peer keys)
dhcrypt derive --priv alice.key --peer bob.pub --fingerprint -o secret.bin

# 4. Encrypt message
dhcrypt encrypt -k secret.bin -p message.txt -o message.enc

# 5. Decrypt message
dhcrypt decrypt -k secret.bin -p message.enc -o recovered.txt
```

---

## Command-Line Interface Reference

```
usage: dhcrypt [-h] {genparams,keygen,derive,encrypt,decrypt} ...
```

### `genparams`
Generate safe-prime Diffie-Hellman parameters serialized in PKCS#3 PEM format.

```bash
dhcrypt genparams [--bits BITS] [-o OUT]
```

- `--bits`: Bit length of the prime modulus (default: `2048`).
- `-o`, `--out`: Output path (`-` for stdout, default: `-`).

### `keygen`
Generate a private key (PKCS#8 format, mode 0600) and public key (SPKI format) from group parameters.

```bash
dhcrypt keygen -p PARAMS --priv PRIV --pub PUB [--private-length BITS] [--force]
```

- `-p`, `--params`: Path to DH parameters PEM (or any DH key PEM carrying parameters).
- `--priv`: Output path for the private key (mode 0600).
- `--pub`: Output path for the public key.
- `--private-length`: Exponent bit length (e.g., `256` for short exponent generation).
- `--force`: Overwrite existing private key file if present.

### `derive`
Derive the raw shared secret between our private key and a peer's public key.

```bash
dhcrypt derive --priv PRIV --peer PEER [-o OUT] [--hex] [--fingerprint] [--strip-zeros]
```

- `--priv`: Path to our private key PEM.
- `--peer`: Path to peer's public key PEM.
- `-o`, `--out`: Output path (`-` for stdout).
- `--hex`: Encode secret as hexadecimal text.
- `--fingerprint`: Output SHA-256 fingerprint of the shared secret to stderr.
- `--strip-zeros`: Strip leading zero bytes (reproduces legacy OpenSSL 1.x / `DH_compute_key` behavior).

### `encrypt`
Encrypt a payload using AES-256-GCM.

```bash
# Using derived secret file:
dhcrypt encrypt -k SECRET -p PAYLOAD [-o OUT]

# Or deriving directly from keys:
dhcrypt encrypt --priv PRIV --peer PEER -p PAYLOAD [-o OUT]
```

- `-k`, `--pem`: Path to file containing the shared secret (raw bytes or hex).
- `--priv` and `--peer`: Derive secret directly using our private key and peer's public key.
- `-p`, `--payload`: Path to input plaintext (`-` for stdin).
- `-o`, `--out`: Path to output ciphertext (`-` for stdout).

### `decrypt`
Verify authentication tag and decrypt an AES-256-GCM ciphertext payload.

```bash
# Using derived secret file:
dhcrypt decrypt -k SECRET -p PAYLOAD [-o OUT]

# Or deriving directly from keys:
dhcrypt decrypt --priv PRIV --peer PEER -p PAYLOAD [-o OUT]
```

---

## Python API Usage

`dhcrypt` can be imported and integrated directly into Python applications:

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

# 2. Parties generate keypairs
alice_priv, alice_pub, alice_bits = generate_keypair_pem(params_pem)
bob_priv, bob_pub, bob_bits = generate_keypair_pem(params_pem)

# 3. Derive identical shared secrets
secret_alice = derive_shared_secret(alice_priv, bob_pub)
secret_bob = derive_shared_secret(bob_priv, alice_pub)
assert secret_alice == secret_bob

# 4. Encrypt and decrypt payloads
plaintext = b"Encrypted transmission over secure channel."
ciphertext = encrypt_message(secret_alice, plaintext)

decrypted = decrypt_message(secret_bob, ciphertext)
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

params = DHParams(p=0xFFFFFFFFFFFFFFFF, g=2)
validate_peer_public(peer_public_int, params)
raw_secret = compute_shared_secret(private_int, peer_public_int, params)

# HKDF key derivation & AES-GCM
key = derive_symmetric_key(raw_secret, salt=b"custom-salt", info=b"app-context")
encrypted = encrypt_payload(key, b"Sensitive data")
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

## Test Suite & Quality Assurance

Run the test suite with coverage reporting:

```bash
poetry run pytest
```

### Test Coverage Summary

```
Name                       Stmts   Miss  Cover
----------------------------------------------
dhcrypt\__init__.py           14      0   100%
dhcrypt\__main__.py            2      0   100%
dhcrypt\cli.py                89      0   100%
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
TOTAL                        433      0   100%
```

---

## License

MIT License. Copyright (c) 2026 DJ Stomp.
