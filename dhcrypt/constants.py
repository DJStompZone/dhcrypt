"""Constants and default configuration parameters for cryptographic operations."""

DEFAULT_HKDF_INFO: bytes = b"stompzone-dh-kex-context"

AES_GCM_NONCE_LENGTH: int = 12

AES_GCM_TAG_LENGTH: int = 16

DERIVED_KEY_LENGTH: int = 32

DEFAULT_GENERATOR: int = 2

DEFAULT_KEY_SIZE: int = 2048
