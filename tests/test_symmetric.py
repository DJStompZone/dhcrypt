"""Unit tests for symmetric key derivation and AEAD authenticated encryption."""

import pytest
from dhcrypt.constants import AES_GCM_NONCE_LENGTH, AES_GCM_TAG_LENGTH
from dhcrypt.exceptions import DHCryptoError
from dhcrypt.symmetric import (
    AESGCMSymmetricCipher,
    SymmetricCipher,
    decrypt_payload,
    derive_symmetric_key,
    encrypt_payload,
)


def test_derive_symmetric_key_defaults_and_custom() -> None:
    """Tests HKDF key derivation with default and custom salt/info parameters."""
    secret = b"test-shared-secret-bytes-12345678"
    key1 = derive_symmetric_key(secret)
    key2 = derive_symmetric_key(secret)
    assert len(key1) == 32
    assert key1 == key2

    key_salted = derive_symmetric_key(secret, salt=b"random-salt")
    assert key_salted != key1

    key_custom_info = derive_symmetric_key(secret, info=b"custom-info")
    assert key_custom_info != key1


def test_derive_symmetric_key_error() -> None:
    """Verifies that key derivation errors raise DHCryptoError when length exceeds maximum."""
    with pytest.raises(DHCryptoError, match="key derivation failed"):
        derive_symmetric_key(b"secret", length=100000)


def test_aes_gcm_encrypt_decrypt_round_trip() -> None:
    """Tests AES-256-GCM encryption and decryption round trip."""
    key = b"\x01" * 32
    plaintext = b"Hello, secure world! This is a test message."

    encrypted = encrypt_payload(key, plaintext)
    assert len(encrypted) == AES_GCM_NONCE_LENGTH + len(plaintext) + AES_GCM_TAG_LENGTH

    decrypted = decrypt_payload(key, encrypted)
    assert decrypted == plaintext


def test_aes_gcm_decrypt_too_short() -> None:
    """Ensures payloads shorter than nonce + tag length are rejected."""
    key = b"\x01" * 32
    too_short_payload = b"\x00" * (AES_GCM_NONCE_LENGTH + AES_GCM_TAG_LENGTH - 1)

    with pytest.raises(DHCryptoError, match="payload is too short"):
        decrypt_payload(key, too_short_payload)


def test_aes_gcm_decrypt_tampered_tag() -> None:
    """Ensures tampering with ciphertext or tag raises an authentication error."""
    key = b"\x01" * 32
    plaintext = b"Authentic message"
    encrypted = bytearray(encrypt_payload(key, plaintext))

    encrypted[-1] ^= 0x01

    with pytest.raises(DHCryptoError, match="invalid authentication tag"):
        decrypt_payload(key, bytes(encrypted))


def test_aes_gcm_cipher_invalid_key_length() -> None:
    """Tests that invalid key lengths cause DHCryptoError in encrypt and decrypt."""
    invalid_key = b"short-key"
    plaintext = b"Payload data"
    cipher = AESGCMSymmetricCipher()

    with pytest.raises(DHCryptoError, match="encryption failed"):
        cipher.encrypt(invalid_key, plaintext)

    valid_payload = b"\x00" * 40
    with pytest.raises(DHCryptoError, match="decryption failed"):
        cipher.decrypt(invalid_key, valid_payload)


class MockCipher:
    """Mock cipher implementing the SymmetricCipher protocol for testing."""

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Mock encryption returning reversed plaintext."""
        return plaintext[::-1]

    def decrypt(self, key: bytes, encrypted_payload: bytes) -> bytes:
        """Mock decryption returning reversed ciphertext."""
        return encrypted_payload[::-1]


def test_custom_symmetric_cipher_injection() -> None:
    """Verifies that custom cipher protocol implementations can be injected."""
    mock_cipher: SymmetricCipher = MockCipher()
    key = b"dummy-key"
    plaintext = b"Custom cipher payload"

    encrypted = encrypt_payload(key, plaintext, cipher=mock_cipher)
    assert encrypted == plaintext[::-1]

    decrypted = decrypt_payload(key, encrypted, cipher=mock_cipher)
    assert decrypted == plaintext
