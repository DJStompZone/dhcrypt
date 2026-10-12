"""Cryptographic mathematics, primality testing, and validation routines."""

import secrets
from dhcrypt.exceptions import DHParameterError, DHValidationError
from dhcrypt.models import DHParams


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Performs the Miller-Rabin probabilistic primality test on an integer.

    Args:
        n: The integer to test for primality.
        rounds: Number of testing rounds to perform for confidence.

    Returns:
        True if the integer is probably prime, False if composite.
    """
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def validate_peer_public(y: int, params: DHParams) -> None:
    """Validates a peer's public key value against group parameters.

    Rejects degenerate or out-of-subgroup peer public values. Always enforces
    2 <= y <= p - 2. When p is a safe prime and g generates the order-q subgroup,
    also requires y^q == 1 (mod p) to prevent small-subgroup confinement.

    Args:
        y: Peer public key integer.
        params: Diffie-Hellman parameters containing modulus p and generator g.

    Raises:
        DHValidationError: If public value is out of range or not in prime subgroup.
    """
    p = params.p
    if not 2 <= y <= p - 2:
        raise DHValidationError("peer public value is out of range (possible attack)")
    q = (p - 1) // 2
    if pow(params.g, q, p) == 1 and is_probable_prime(q) and pow(y, q, p) != 1:
        raise DHValidationError("peer public value is not in the prime-order subgroup")


def generate_private_exponent(params: DHParams) -> int:
    """Generates a random private exponent conforming to parameter length constraints.

    If length is None, a full-range private exponent in [2, p - 2] is chosen.
    If length is specified, an exponent of exact bit length is generated.

    Args:
        params: Diffie-Hellman parameters specifying modulus p and optional exponent bit length.

    Returns:
        Generated private exponent integer x.

    Raises:
        DHParameterError: If requested private length is invalid for prime modulus.
    """
    if params.length is None:
        if params.p <= 3:
            raise DHParameterError("prime modulus too small for exponent generation")
        return secrets.randbelow(params.p - 3) + 2
    bits = params.length
    if not 2 <= bits < params.p.bit_length():
        raise DHParameterError(f"private length {bits} is out of range for this prime")
    while True:
        x = secrets.randbits(bits) | (1 << (bits - 1))
        if 1 < x < params.p - 1:
            return x


def compute_shared_secret(
    x: int, y: int, params: DHParams, strip_zeros: bool = False
) -> bytes:
    """Computes raw Diffie-Hellman shared secret bytes.

    Args:
        x: Our private exponent integer.
        y: Peer public key integer.
        params: Diffie-Hellman group parameters.
        strip_zeros: Whether to strip leading zero bytes (legacy OpenSSL 1.x compatibility).

    Returns:
        Big-endian byte representation of derived shared secret z = y^x mod p.

    Raises:
        DHValidationError: If peer public value is invalid or shared secret is degenerate.
    """
    validate_peer_public(y, params)
    z = pow(y, x, params.p)
    if z in (0, 1, params.p - 1):
        raise DHValidationError("degenerate shared secret")
    if strip_zeros:
        size = (z.bit_length() + 7) // 8
    else:
        size = params.byte_length
    return z.to_bytes(size, "big")
