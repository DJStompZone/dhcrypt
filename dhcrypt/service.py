"""Service layer providing high-level cryptographic operations."""

import warnings
from dhcrypt.dh import (
    compute_shared_from_keys,
    generate_parameters,
    generate_private_key,
)
from dhcrypt.models import DHParams
from dhcrypt.serialization import (
    load_params_from_bytes,
    serialize_params_pkcs3_pem,
    serialize_private_pkcs8_pem,
    serialize_public_spki_pem,
)
from dhcrypt.symmetric import (
    decrypt_payload,
    derive_symmetric_key,
    encrypt_payload,
)


def generate_parameters_pem(key_size: int = 2048) -> bytes:
    """Generates Diffie-Hellman parameters serialized to PKCS#3 PEM.

    Args:
        key_size: Bit size of the prime modulus (defaults to 2048).

    Returns:
        PEM encoded parameter bytes.
    """
    params = generate_parameters(key_size=key_size)
    return serialize_params_pkcs3_pem(params)


def generate_keypair_pem(
    params_pem: bytes, private_length: int | None = None
) -> tuple[bytes, bytes, int]:
    """Generates a keypair from PEM parameters and returns PEM representations.

    Args:
        params_pem: Parameter PEM bytes or key PEM containing parameters.
        private_length: Optional exponent bit length override.

    Returns:
        Tuple of (private_key_pkcs8_pem, public_key_spki_pem, exponent_bit_length).
    """
    params = load_params_from_bytes(params_pem)
    if private_length is not None:
        params = DHParams(params.p, params.g, private_length)
    key = generate_private_key(params)
    priv_pem = serialize_private_pkcs8_pem(key)
    pub_pem = serialize_public_spki_pem(key)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=Warning)
        bits = key.private_numbers().x.bit_length()
    return priv_pem, pub_pem, bits


def derive_shared_secret(
    priv_pem: bytes, peer_pem: bytes, strip_zeros: bool = False
) -> bytes:
    """Derives the raw Diffie-Hellman shared secret from private and public PEM keys.

    Args:
        priv_pem: Private key PEM bytes.
        peer_pem: Peer public key PEM bytes.
        strip_zeros: Whether to strip leading zeros (legacy OpenSSL 1.x compatibility).

    Returns:
        Raw shared secret bytes.
    """
    return compute_shared_from_keys(priv_pem, peer_pem, strip_zeros=strip_zeros)


def encrypt_message(secret: bytes, plaintext: bytes) -> bytes:
    """Derives an AES-256 key from a shared secret and encrypts plaintext.

    Args:
        secret: Raw shared secret or pre-shared key bytes.
        plaintext: Plaintext bytes to encrypt.

    Returns:
        Nonce and ciphertext payload bytes.
    """
    key = derive_symmetric_key(secret)
    return encrypt_payload(key, plaintext)


def decrypt_message(secret: bytes, ciphertext: bytes) -> bytes:
    """Derives an AES-256 key from a shared secret and decrypts ciphertext.

    Args:
        secret: Raw shared secret or pre-shared key bytes.
        ciphertext: Nonce and ciphertext payload bytes.

    Returns:
        Decrypted plaintext bytes.
    """
    key = derive_symmetric_key(secret)
    return decrypt_payload(key, ciphertext)
