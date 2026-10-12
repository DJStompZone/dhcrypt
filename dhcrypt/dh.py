"""Diffie-Hellman key exchange operations and key generation."""

import warnings
from cryptography.hazmat.primitives.asymmetric import dh
from dhcrypt.constants import DEFAULT_GENERATOR, DEFAULT_KEY_SIZE
from dhcrypt.exceptions import DHKeyError, DHParameterError
from dhcrypt.math import compute_shared_secret, generate_private_exponent
from dhcrypt.models import DHParams
from dhcrypt.serialization import load_peer_from_bytes, load_private_from_bytes


def generate_parameters(
    key_size: int = DEFAULT_KEY_SIZE, generator: int = DEFAULT_GENERATOR
) -> dh.DHParameters:
    """Generates standard safe-prime Diffie-Hellman parameters.

    Args:
        key_size: Bit length of the prime modulus p (defaults to 2048).
        generator: Small integer generator g (defaults to 2).

    Returns:
        Cryptography DHParameters instance.

    Raises:
        DHParameterError: If parameter generation fails.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=Warning)
            return dh.generate_parameters(generator=generator, key_size=key_size)
    except Exception as exc:
        raise DHParameterError(f"failed to generate DH parameters: {exc}") from exc


def generate_private_key(params: DHParams) -> dh.DHPrivateKey:
    """Generates a Diffie-Hellman private key from DH group parameters.

    If length is omitted in params, OpenSSL and cryptography defaults are used.
    If length is specified, an exponent of exact bit length is generated and
    the corresponding public component is computed.

    Args:
        params: DHParams defining prime p, generator g, and optional exponent length.

    Returns:
        Cryptography DHPrivateKey instance.

    Raises:
        DHKeyError: If key generation fails.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=Warning)
            if params.length is None:
                return params.numbers().parameters().generate_private_key()
            x = generate_private_exponent(params)
            y = pow(params.g, x, params.p)
            public_numbers = dh.DHPublicNumbers(y, params.numbers())
            private_numbers = dh.DHPrivateNumbers(x, public_numbers)
            return private_numbers.private_key()
    except Exception as exc:
        raise DHKeyError(f"failed to generate private key: {exc}") from exc


def compute_shared_from_keys(
    priv_bytes: bytes, peer_bytes: bytes, strip_zeros: bool = False
) -> bytes:
    """Computes a raw shared secret from private key and peer public key PEM bytes.

    Args:
        priv_bytes: PEM-encoded private key bytes.
        peer_bytes: PEM-encoded peer public key bytes.
        strip_zeros: Whether to strip leading zero bytes (OpenSSL 1.x compatibility).

    Returns:
        Derived shared secret bytes.

    Raises:
        DHParameterError: If parameter groups do not match between keys.
    """
    x, ours = load_private_from_bytes(priv_bytes)
    y, theirs = load_peer_from_bytes(peer_bytes)
    if (ours.p, ours.g) != (theirs.p, theirs.g):
        raise DHParameterError(
            "private key and peer public key use different DH parameters"
        )
    return compute_shared_secret(x, y, ours, strip_zeros=strip_zeros)
