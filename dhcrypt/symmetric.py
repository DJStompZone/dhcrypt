"""Symmetric key derivation and authenticated encryption operations."""

import os
from typing import Protocol
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dhcrypt.constants import (
    AES_GCM_NONCE_LENGTH,
    AES_GCM_TAG_LENGTH,
    DEFAULT_HKDF_INFO,
    DERIVED_KEY_LENGTH,
)
from dhcrypt.exceptions import DHCryptoError


class SymmetricCipher(Protocol):
    """Protocol defining symmetric authenticated encryption and decryption operations."""

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts plaintext using the provided key.

        Args:
            key: Symmetric key bytes.
            plaintext: Plaintext bytes to encrypt.

        Returns:
            Encrypted ciphertext bytes including nonce and authentication tag.
        """
        pass

    def decrypt(self, key: bytes, encrypted_payload: bytes) -> bytes:
        """Decrypts payload using the provided key.

        Args:
            key: Symmetric key bytes.
            encrypted_payload: Encrypted ciphertext bytes.

        Returns:
            Decrypted plaintext bytes.
        """
        pass


class AESGCMSymmetricCipher:
    """AES-256-GCM authenticated cipher implementation."""

    def __init__(self, nonce_length: int = AES_GCM_NONCE_LENGTH) -> None:
        """Initializes the AES-GCM cipher with configured nonce length.

        Args:
            nonce_length: Length of random nonce in bytes (defaults to 12).
        """
        self._nonce_length = nonce_length

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts plaintext using AES-256-GCM.

        Prepends a randomly generated nonce to the AES-GCM ciphertext and tag.

        Args:
            key: 32-byte symmetric key.
            plaintext: Plaintext bytes to encrypt.

        Returns:
            Combined byte payload: nonce || ciphertext || tag.

        Raises:
            DHCryptoError: If encryption fails or key length is invalid.
        """
        try:
            nonce = os.urandom(self._nonce_length)
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
            return nonce + ciphertext
        except Exception as exc:
            raise DHCryptoError(f"encryption failed: {exc}") from exc

    def decrypt(self, key: bytes, encrypted_payload: bytes) -> bytes:
        """Decrypts a payload encrypted with AES-256-GCM.

        Extracts the initial nonce and authenticates/decrypts the remainder.

        Args:
            key: 32-byte symmetric key.
            encrypted_payload: Combined byte payload: nonce || ciphertext || tag.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            DHCryptoError: If payload is too short, key is invalid, or authentication tag fails.
        """
        min_length = self._nonce_length + AES_GCM_TAG_LENGTH
        if len(encrypted_payload) < min_length:
            raise DHCryptoError("payload is too short to be valid")
        nonce = encrypted_payload[: self._nonce_length]
        ciphertext = encrypted_payload[self._nonce_length :]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise DHCryptoError(
                "decryption failed: invalid authentication tag (wrong key or corrupted payload)"
            ) from exc
        except Exception as exc:
            raise DHCryptoError(f"decryption failed: {exc}") from exc


_DEFAULT_CIPHER = AESGCMSymmetricCipher()


def derive_symmetric_key(
    shared_secret: bytes,
    salt: bytes | None = None,
    info: bytes = DEFAULT_HKDF_INFO,
    length: int = DERIVED_KEY_LENGTH,
) -> bytes:
    """Derives a symmetric key from a shared secret using HKDF-SHA256.

    Args:
        shared_secret: Raw shared secret bytes obtained from key agreement.
        salt: Optional cryptographic salt. Should be shared publicly if used.
        info: Optional application-specific context info.
        length: Desired key length in bytes (defaults to 32 bytes for AES-256).

    Returns:
        Derived symmetric key bytes.

    Raises:
        DHCryptoError: If key derivation fails.
    """
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_secret)
    except Exception as exc:
        raise DHCryptoError(f"key derivation failed: {exc}") from exc


def encrypt_payload(
    key: bytes, plaintext: bytes, cipher: SymmetricCipher = _DEFAULT_CIPHER
) -> bytes:
    """Convenience function encrypting plaintext using configured symmetric cipher.

    Args:
        key: Symmetric key bytes.
        plaintext: Plaintext bytes to encrypt.
        cipher: SymmetricCipher implementation (defaults to AES-GCM).

    Returns:
        Combined ciphertext payload bytes.
    """
    return cipher.encrypt(key, plaintext)


def decrypt_payload(
    key: bytes, encrypted_payload: bytes, cipher: SymmetricCipher = _DEFAULT_CIPHER
) -> bytes:
    """Convenience function decrypting payload using configured symmetric cipher.

    Args:
        key: Symmetric key bytes.
        encrypted_payload: Ciphertext payload bytes.
        cipher: SymmetricCipher implementation (defaults to AES-GCM).

    Returns:
        Decrypted plaintext bytes.
    """
    return cipher.decrypt(key, encrypted_payload)
