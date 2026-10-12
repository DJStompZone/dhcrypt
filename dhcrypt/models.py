"""Domain models representing cryptographic parameters and key exchange data."""

from dataclasses import dataclass
import warnings
from cryptography.hazmat.primitives.asymmetric import dh


@dataclass(frozen=True)
class DHParams:
    """Represents Diffie-Hellman group parameters.

    Attributes:
        p: Prime modulus integer.
        g: Generator integer.
        length: Optional private exponent bit length specified in PKCS#3 parameters.
    """

    p: int
    g: int
    length: int | None = None

    def numbers(self) -> dh.DHParameterNumbers:
        """Constructs cryptography DHParameterNumbers from this instance.

        Returns:
            DHParameterNumbers instance encapsulating prime p and generator g.
        """
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=Warning)
            return dh.DHParameterNumbers(self.p, self.g)

    @property
    def bit_length(self) -> int:
        """Calculates the bit length of the prime modulus p.

        Returns:
            Bit length of prime modulus p.
        """
        return self.p.bit_length()

    @property
    def byte_length(self) -> int:
        """Calculates the byte length required to represent prime modulus p.

        Returns:
            Byte length of prime modulus p.
        """
        return (self.p.bit_length() + 7) // 8
