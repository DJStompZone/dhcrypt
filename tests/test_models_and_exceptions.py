"""Unit tests for domain models and exception hierarchy."""

from dataclasses import FrozenInstanceError
import pytest
from cryptography.hazmat.primitives.asymmetric import dh
from dhcrypt.exceptions import (
    DHCryptoError,
    DHError,
    DHIOError,
    DHKeyError,
    DHParameterError,
    DHValidationError,
)
from dhcrypt.models import DHParams


def test_exception_hierarchy() -> None:
    """Verifies that all specialized exceptions inherit from base DHError."""
    assert issubclass(DHParameterError, DHError)
    assert issubclass(DHKeyError, DHError)
    assert issubclass(DHValidationError, DHError)
    assert issubclass(DHCryptoError, DHError)
    assert issubclass(DHIOError, DHError)

    err = DHParameterError("invalid parameter")
    assert isinstance(err, DHError)


def test_dhparams_properties() -> None:
    """Tests DHParams properties including bit length and byte length calculations."""
    p = 0xFFFFFFFFFFFFFFFF
    g = 2
    params = DHParams(p=p, g=g, length=128)

    assert params.p == p
    assert params.g == g
    assert params.length == 128
    assert params.bit_length == 64
    assert params.byte_length == 8


def test_dhparams_numbers() -> None:
    """Tests generation of cryptography DHParameterNumbers from DHParams."""
    raw_params = dh.generate_parameters(generator=2, key_size=512)
    p = raw_params.parameter_numbers().p
    g = raw_params.parameter_numbers().g
    params = DHParams(p=p, g=g)
    numbers = params.numbers()

    assert numbers.p == p
    assert numbers.g == g


def test_dhparams_immutability() -> None:
    """Ensures DHParams instances are immutable frozen dataclasses."""
    params = DHParams(p=23, g=5)
    with pytest.raises(FrozenInstanceError):
        setattr(params, "p", 29)
