"""dhcrypt: OpenSSL-interoperable Diffie-Hellman key exchange and AES-256-GCM encryption.

A production-ready cryptographic library and command-line utility providing
finite-field Diffie-Hellman parameter generation, key generation, key agreement,
and authenticated symmetric encryption.
"""

from __future__ import annotations

import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from dhcrypt.constants import (
    AES_GCM_NONCE_LENGTH,
    AES_GCM_TAG_LENGTH,
    DEFAULT_GENERATOR,
    DEFAULT_HKDF_INFO,
    DEFAULT_KEY_SIZE,
    DERIVED_KEY_LENGTH,
)
from dhcrypt.dh import (
    compute_shared_from_keys,
    generate_parameters,
    generate_private_key,
)
from dhcrypt.exceptions import (
    DHCryptoError,
    DHError,
    DHIOError,
    DHKeyError,
    DHParameterError,
    DHValidationError,
)
from dhcrypt.math import (
    compute_shared_secret,
    generate_private_exponent,
    is_probable_prime,
    validate_peer_public,
)
from dhcrypt.models import DHParams
from dhcrypt.serialization import (
    load_params_from_bytes,
    load_peer_from_bytes,
    load_private_from_bytes,
    parse_pkcs3_der,
    parse_secret_bytes,
    serialize_params_pkcs3_pem,
    serialize_private_pkcs8_pem,
    serialize_public_spki_pem,
)
from dhcrypt.service import (
    decrypt_message,
    derive_shared_secret,
    encrypt_message,
    generate_keypair_pem,
    generate_parameters_pem,
)
from dhcrypt.symmetric import (
    AESGCMSymmetricCipher,
    SymmetricCipher,
    decrypt_payload,
    derive_symmetric_key,
    encrypt_payload,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AES_GCM_NONCE_LENGTH",
    "AES_GCM_TAG_LENGTH",
    "DEFAULT_GENERATOR",
    "DEFAULT_HKDF_INFO",
    "DEFAULT_KEY_SIZE",
    "DERIVED_KEY_LENGTH",
    "DHError",
    "DHParameterError",
    "DHKeyError",
    "DHValidationError",
    "DHCryptoError",
    "DHIOError",
    "DHParams",
    "SymmetricCipher",
    "AESGCMSymmetricCipher",
    "is_probable_prime",
    "validate_peer_public",
    "generate_private_exponent",
    "compute_shared_secret",
    "parse_pkcs3_der",
    "load_params_from_bytes",
    "load_private_from_bytes",
    "load_peer_from_bytes",
    "serialize_params_pkcs3_pem",
    "serialize_private_pkcs8_pem",
    "serialize_public_spki_pem",
    "parse_secret_bytes",
    "derive_symmetric_key",
    "encrypt_payload",
    "decrypt_payload",
    "generate_parameters",
    "generate_private_key",
    "compute_shared_from_keys",
    "generate_parameters_pem",
    "generate_keypair_pem",
    "derive_shared_secret",
    "encrypt_message",
    "decrypt_message",
]
