"""Unit tests for mathematical routines, primality checks, and public key validation."""

import pytest
from dhcrypt.exceptions import DHParameterError, DHValidationError
from dhcrypt.math import (
    compute_shared_secret,
    generate_private_exponent,
    is_probable_prime,
    validate_peer_public,
)
from dhcrypt.models import DHParams


def test_is_probable_prime_edge_cases() -> None:
    """Tests primality verification on edge integers and small numbers."""
    assert not is_probable_prime(-5)
    assert not is_probable_prime(0)
    assert not is_probable_prime(1)
    assert is_probable_prime(2)
    assert is_probable_prime(3)
    assert not is_probable_prime(4)
    assert not is_probable_prime(100)


def test_is_probable_prime_primes_and_composites() -> None:
    """Tests primality testing against known primes and Carmichael composites."""
    primes = [5, 7, 11, 13, 23, 29, 31, 65537]
    for prime_val in primes:
        assert is_probable_prime(prime_val)

    composites = [9, 15, 21, 25, 27, 561]
    for composite_val in composites:
        assert not is_probable_prime(composite_val)


def test_validate_peer_public_range() -> None:
    """Ensures peer public keys outside the range [2, p - 2] are rejected."""
    params = DHParams(p=23, g=5)

    with pytest.raises(DHValidationError, match="out of range"):
        validate_peer_public(1, params)

    with pytest.raises(DHValidationError, match="out of range"):
        validate_peer_public(22, params)

    with pytest.raises(DHValidationError, match="out of range"):
        validate_peer_public(25, params)


def test_validate_peer_public_subgroup() -> None:
    """Verifies that non-subgroup public elements are rejected for safe primes."""
    safe_p = 23
    generator = 2
    params = DHParams(p=safe_p, g=generator)

    valid_subgroup_y = 4
    validate_peer_public(valid_subgroup_y, params)

    non_subgroup_y = 5
    with pytest.raises(DHValidationError, match="not in the prime-order subgroup"):
        validate_peer_public(non_subgroup_y, params)


def test_generate_private_exponent_default() -> None:
    """Tests exponent generation when no length hint is specified."""
    params = DHParams(p=23, g=5)
    exponent = generate_private_exponent(params)
    assert 1 < exponent < params.p - 1


def test_generate_private_exponent_small_modulus() -> None:
    """Tests that exponent generation fails if modulus p is too small."""
    params = DHParams(p=3, g=2)
    with pytest.raises(DHParameterError, match="too small"):
        generate_private_exponent(params)


def test_generate_private_exponent_custom_length() -> None:
    """Tests exponent generation with custom bit length specification."""
    params = DHParams(p=0xFFFFFFFFFFFFFFFFFFFFFFFF, g=2, length=16)
    exponent = generate_private_exponent(params)
    assert exponent.bit_length() == 16
    assert 1 < exponent < params.p - 1


def test_generate_private_exponent_invalid_lengths() -> None:
    """Tests rejection of exponent bit lengths that are too small or too large."""
    params = DHParams(p=23, g=5)

    invalid_params_small = DHParams(p=23, g=5, length=1)
    with pytest.raises(DHParameterError, match="out of range"):
        generate_private_exponent(invalid_params_small)

    invalid_params_large = DHParams(p=23, g=5, length=10)
    with pytest.raises(DHParameterError, match="out of range"):
        generate_private_exponent(invalid_params_large)


def test_compute_shared_secret_normal_and_stripped() -> None:
    """Tests shared secret computation with standard and stripped zero modes."""
    params = DHParams(p=23, g=2)
    x = 3
    y = 4

    secret = compute_shared_secret(x, y, params, strip_zeros=False)
    expected = pow(y, x, 23).to_bytes(params.byte_length, "big")
    assert secret == expected

    stripped_secret = compute_shared_secret(x, y, params, strip_zeros=True)
    expected_stripped = pow(y, x, 23).to_bytes(
        (pow(y, x, 23).bit_length() + 7) // 8, "big"
    )
    assert stripped_secret == expected_stripped


def test_compute_shared_secret_degenerate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies rejection of degenerate shared secret values."""
    params = DHParams(p=23, g=2)
    x = 3
    y = 4

    monkeypatch.setattr("builtins.pow", lambda base, exp, mod: 1)
    with pytest.raises(DHValidationError, match="degenerate shared secret"):
        compute_shared_secret(x, y, params)
