"""Serialization and deserialization routines for ASN.1 DER and PEM formats."""

import base64
from typing import Any, cast
import warnings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from dhcrypt.exceptions import DHKeyError, DHParameterError
from dhcrypt.models import DHParams


def der_read_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Reads a single DER tag-length-value header.

    Args:
        buf: The raw DER encoded bytes.
        pos: The starting index in the buffer.

    Returns:
        A tuple of (tag, content_start_offset, content_end_offset).

    Raises:
        DHParameterError: If the DER stream is truncated or malformed.
    """
    try:
        tag = buf[pos]
        size = buf[pos + 1]
        pos += 2
        if size & 0x80:
            count = size & 0x7F
            size = int.from_bytes(buf[pos : pos + count], "big")
            pos += count
    except IndexError as exc:
        raise DHParameterError("truncated DH parameters") from exc
    if pos + size > len(buf):
        raise DHParameterError("truncated DH parameters")
    return tag, pos, pos + size


def parse_pkcs3_der(der: bytes) -> DHParams:
    """Parses a PKCS#3 DHParameter ASN.1 SEQUENCE.

    The ASN.1 structure conforms to:
    DHParameter ::= SEQUENCE {
        p INTEGER,
        g INTEGER,
        privateValueLength INTEGER OPTIONAL
    }

    Args:
        der: The raw DER-encoded PKCS#3 parameter bytes.

    Returns:
        DHParams instance containing prime p, generator g, and optional private length.

    Raises:
        DHParameterError: If structure is malformed or integers cannot be parsed.
    """
    tag, pos, end = der_read_tlv(der, 0)
    if tag != 0x30:
        raise DHParameterError("DH parameters: expected a SEQUENCE")
    ints: list[int] = []
    while pos < end:
        tag, start, stop = der_read_tlv(der, pos)
        if tag != 0x02:
            raise DHParameterError("DH parameters: expected INTEGERs")
        ints.append(int.from_bytes(der[start:stop], "big"))
        pos = stop
    if len(ints) not in (2, 3):
        raise DHParameterError("DH parameters: expected p, g[, privateValueLength]")
    return DHParams(ints[0], ints[1], ints[2] if len(ints) == 3 else None)


def load_params_from_bytes(data: bytes) -> DHParams:
    """Loads Diffie-Hellman parameters from raw bytes or PEM text.

    Accepts standard 'DH PARAMETERS' PEM blocks, PKCS#8 private keys,
    SubjectPublicKeyInfo public keys, or legacy parameter blocks.

    Args:
        data: Raw PEM bytes or DER bytes.

    Returns:
        Parsed DHParams instance.

    Raises:
        DHParameterError: If the provided data cannot be parsed as valid DH parameters.
    """
    text = data.decode("ascii", errors="ignore")
    marker = "-----BEGIN DH PARAMETERS-----"
    try:
        if marker in text:
            body = text.split(marker, 1)[1].split("-----END", 1)[0]
            return parse_pkcs3_der(base64.b64decode("".join(body.split())))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=Warning)
            if "PRIVATE KEY" in text:
                priv_key = serialization.load_pem_private_key(data, None)
                params_obj: Any = priv_key.parameters()
                nums = params_obj.parameter_numbers()
            elif "PUBLIC KEY" in text:
                pub_key = serialization.load_pem_public_key(data)
                params_obj = pub_key.parameters()
                nums = params_obj.parameter_numbers()
            else:
                nums = serialization.load_pem_parameters(data).parameter_numbers()
    except DHParameterError:
        raise
    except Exception as exc:
        raise DHParameterError(f"not usable as DH parameters: {exc}") from exc
    return DHParams(nums.p, nums.g)


def load_private_from_bytes(data: bytes) -> tuple[int, DHParams]:
    """Loads a Diffie-Hellman private key from PEM bytes.

    Args:
        data: PEM-encoded private key data (PKCS#8 or traditional).

    Returns:
        A tuple of (private_exponent_x, dh_params).

    Raises:
        DHKeyError: If private key cannot be parsed or lacks DH parameters.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=Warning)
            key = cast(Any, serialization.load_pem_private_key(data, None))
            numbers = key.private_numbers()
            param_numbers = numbers.public_numbers.parameter_numbers
    except Exception as exc:
        raise DHKeyError(f"not a usable DH private key: {exc}") from exc
    return numbers.x, DHParams(param_numbers.p, param_numbers.g)


def load_peer_from_bytes(data: bytes) -> tuple[int, DHParams]:
    """Loads a peer's Diffie-Hellman public key from PEM bytes.

    Args:
        data: PEM-encoded public key data (SPKI format).

    Returns:
        A tuple of (public_value_y, dh_params).

    Raises:
        DHKeyError: If public key cannot be parsed or lacks DH parameters.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=Warning)
            key = cast(Any, serialization.load_pem_public_key(data))
            numbers = key.public_numbers()
            param_numbers = numbers.parameter_numbers
    except Exception as exc:
        raise DHKeyError(f"not a usable DH public key: {exc}") from exc
    return numbers.y, DHParams(param_numbers.p, param_numbers.g)


def serialize_params_pkcs3_pem(params: dh.DHParameters) -> bytes:
    """Serializes Diffie-Hellman parameters to PKCS#3 PEM format.

    Args:
        params: Cryptography DHParameters instance.

    Returns:
        PEM formatted bytes representing parameters.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=Warning)
        return params.parameter_bytes(
            serialization.Encoding.PEM,
            serialization.ParameterFormat.PKCS3,
        )


def serialize_private_pkcs8_pem(key: dh.DHPrivateKey) -> bytes:
    """Serializes a Diffie-Hellman private key to unencrypted PKCS#8 PEM format.

    Args:
        key: Cryptography DHPrivateKey instance.

    Returns:
        PEM formatted bytes representing private key.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=Warning)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def serialize_public_spki_pem(key: dh.DHPrivateKey | dh.DHPublicKey) -> bytes:
    """Serializes a Diffie-Hellman public key to SubjectPublicKeyInfo PEM format.

    Args:
        key: Cryptography DHPrivateKey or DHPublicKey instance.

    Returns:
        PEM formatted bytes representing public key.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=Warning)
        target = key if isinstance(key, dh.DHPublicKey) else key.public_key()
        return target.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def parse_secret_bytes(data: bytes) -> bytes:
    """Interprets input bytes as either a hex-encoded string or raw binary data.

    Attempts to decode as a UTF-8 hex string first. If that fails or produces
    invalid hex, the raw bytes are returned unmodified to preserve binary data.

    Args:
        data: Secret bytes to decode.

    Returns:
        Decoded binary secret bytes.
    """
    try:
        decoded_text = data.decode("utf-8").strip()
        return bytes.fromhex(decoded_text)
    except (ValueError, UnicodeDecodeError):
        return data
