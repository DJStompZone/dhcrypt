"""Unit tests for high-level service layer operations."""

from dhcrypt.service import (
    decrypt_message,
    derive_shared_secret,
    encrypt_message,
    generate_keypair_pem,
    generate_parameters_pem,
)


def test_service_workflows() -> None:
    """Tests the full end-to-end service layer workflow: params, keygen, derive, encrypt, decrypt."""
    param_pem = generate_parameters_pem(key_size=512)
    assert b"BEGIN DH PARAMETERS" in param_pem

    alice_priv, alice_pub, alice_bits = generate_keypair_pem(param_pem)
    bob_priv, bob_pub, bob_bits = generate_keypair_pem(param_pem, private_length=128)

    assert b"BEGIN PRIVATE KEY" in alice_priv
    assert b"BEGIN PUBLIC KEY" in alice_pub
    assert alice_bits > 0
    assert bob_bits == 128

    secret_alice = derive_shared_secret(alice_priv, bob_pub, strip_zeros=False)
    secret_bob = derive_shared_secret(bob_priv, alice_pub, strip_zeros=False)
    assert secret_alice == secret_bob

    secret_stripped = derive_shared_secret(alice_priv, bob_pub, strip_zeros=True)
    assert secret_stripped == secret_alice.lstrip(b"\x00")

    message = b"Secret service message across end-to-end exchange"
    encrypted = encrypt_message(secret_alice, message)
    decrypted = decrypt_message(secret_bob, encrypted)
    assert decrypted == message
