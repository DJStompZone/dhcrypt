"""Custom exception hierarchy for the dhcrypt package."""


class DHError(Exception):
    """Base exception class for all dhcrypt domain errors."""


class DHParameterError(DHError):
    """Exception raised when Diffie-Hellman parameters are invalid, unsupported, or corrupted."""


class DHKeyError(DHError):
    """Exception raised when Diffie-Hellman key loading, parsing, or generation fails."""


class DHValidationError(DHError):
    """Exception raised when cryptographic parameter or public key validation fails."""


class DHCryptoError(DHError):
    """Exception raised when symmetric key derivation, encryption, or decryption fails."""


class DHIOError(DHError):
    """Exception raised when file or stream input/output operations encounter an error."""
