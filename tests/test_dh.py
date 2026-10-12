"""Unit tests for Diffie-Hellman parameter generation, key generation, and agreement."""

import pytest
from cryptography.hazmat.primitives.asymmetric import dh
from dhcrypt.dh import (
    compute_shared_from_keys,
    generate_parameters,
    generate_private_key,
)
from dhcrypt.exceptions import DHKeyError, DHParameterError
from dhcrypt.models import DHParams
from dhcrypt.serialization import (
    serialize_private_pkcs8_pem,
    serialize_public_spki_pem,
)


def test_generate_parameters_valid() -> None:
    """Tests generating DH parameters with small key size."""
    params = generate_parameters(key_size=512, generator=2)
    numbers = params.parameter_numbers()
    assert numbers.p.bit_length() == 512
    assert numbers.g == 2


def test_generate_parameters_invalid() -> None:
    """Verifies that invalid key size causes DHParameterError."""
    with pytest.raises(DHParameterError, match="failed to generate DH parameters"):
        generate_parameters(key_size=10, generator=2)


def test_generate_private_key_without_and_with_length() -> None:
    """Tests private key generation with and without explicit exponent length."""
    raw_params = dh.generate_parameters(generator=2, key_size=512)
    p = raw_params.parameter_numbers().p
    g = raw_params.parameter_numbers().g

    params_default = DHParams(p=p, g=g, length=None)
    key_default = generate_private_key(params_default)
    assert key_default.private_numbers().x.bit_length() > 0

    params_custom = DHParams(p=p, g=g, length=128)
    key_custom = generate_private_key(params_custom)
    assert key_custom.private_numbers().x.bit_length() == 128


def test_generate_private_key_invalid() -> None:
    """Ensures invalid DHParams trigger DHKeyError during key generation."""
    invalid_params = DHParams(p=10, g=2, length=128)
    with pytest.raises(DHKeyError, match="failed to generate private key"):
        generate_private_key(invalid_params)


def test_compute_shared_from_keys_successful_agreement() -> None:
    """Tests end-to-end key agreement between Alice and Bob producing identical secrets."""
    raw_params = dh.generate_parameters(generator=2, key_size=512)
    p = raw_params.parameter_numbers().p
    g = raw_params.parameter_numbers().g
    params = DHParams(p=p, g=g)

    alice_key = generate_private_key(params)
    bob_key = generate_private_key(params)

    alice_priv_pem = serialize_private_pkcs8_pem(alice_key)
    alice_pub_pem = serialize_public_spki_pem(alice_key)
    bob_priv_pem = serialize_private_pkcs8_pem(bob_key)
    bob_pub_pem = serialize_public_spki_pem(bob_key)

    secret_alice = compute_shared_from_keys(alice_priv_pem, bob_pub_pem)
    secret_bob = compute_shared_from_keys(bob_priv_pem, alice_pub_pem)

    assert secret_alice == secret_bob
    assert len(secret_alice) == params.byte_length


def test_compute_shared_from_keys_mismatched_parameters() -> None:
    """Ensures mismatched parameter groups between keys raise DHParameterError."""
    params_a = dh.generate_parameters(generator=2, key_size=512)
    params_b = dh.generate_parameters(generator=2, key_size=512)

    key_a = params_a.generate_private_key()
    key_b = params_b.generate_private_key()

    priv_a_pem = serialize_private_pkcs8_pem(key_a)
    pub_b_pem = serialize_public_spki_pem(key_b)

    with pytest.raises(DHParameterError, match="different DH parameters"):
        compute_shared_from_keys(priv_a_pem, pub_b_pem)
