"""Unit tests for ASN.1 DER parsing and PEM serialization routines."""

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import dh
from dhcrypt.exceptions import DHKeyError, DHParameterError
from dhcrypt.models import DHParams
from dhcrypt.serialization import (
    der_read_tlv,
    load_params_from_bytes,
    load_peer_from_bytes,
    load_private_from_bytes,
    parse_pkcs3_der,
    parse_secret_bytes,
    serialize_params_pkcs3_pem,
    serialize_private_pkcs8_pem,
    serialize_public_spki_pem,
)


def _encode_der_int(val: int) -> bytes:
    """Helper serializing an integer to minimal big-endian DER INTEGER encoding."""
    raw = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return bytes([0x02, len(raw)]) + raw


def _encode_der_sequence(content: bytes) -> bytes:
    """Helper wrapping content in a DER SEQUENCE."""
    length = len(content)
    if length < 0x80:
        len_bytes = bytes([length])
    else:
        lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
        len_bytes = bytes([0x80 | len(lb)]) + lb
    return bytes([0x30]) + len_bytes + content


def test_der_read_tlv_valid_and_truncated() -> None:
    """Tests DER TLV decoding under normal, long-form, and truncated conditions."""
    short_tlv = b"\x02\x03\x01\x02\x03"
    tag, start, stop = der_read_tlv(short_tlv, 0)
    assert tag == 0x02
    assert start == 2
    assert stop == 5

    long_payload = b"\x01" * 300
    long_tlv = bytes([0x04, 0x82, 0x01, 0x2C]) + long_payload
    tag, start, stop = der_read_tlv(long_tlv, 0)
    assert tag == 0x04
    assert start == 4
    assert stop == 304

    with pytest.raises(DHParameterError, match="truncated"):
        der_read_tlv(b"\x02", 0)

    with pytest.raises(DHParameterError, match="truncated"):
        der_read_tlv(b"\x02\x05\x01\x02", 0)


def test_parse_pkcs3_der_valid_two_and_three_integers() -> None:
    """Tests parsing valid PKCS#3 DER containing two or three integers."""
    der_two = _encode_der_sequence(_encode_der_int(23) + _encode_der_int(5))
    params_two = parse_pkcs3_der(der_two)
    assert params_two.p == 23
    assert params_two.g == 5
    assert params_two.length is None

    der_three = _encode_der_sequence(
        _encode_der_int(23) + _encode_der_int(5) + _encode_der_int(128)
    )
    params_three = parse_pkcs3_der(der_three)
    assert params_three.p == 23
    assert params_three.g == 5
    assert params_three.length == 128


def test_parse_pkcs3_der_malformed_structures() -> None:
    """Tests error handling for malformed PKCS#3 DER structures."""
    non_sequence = bytes([0x31, 0x06]) + _encode_der_int(23) + _encode_der_int(5)
    with pytest.raises(DHParameterError, match="expected a SEQUENCE"):
        parse_pkcs3_der(non_sequence)

    non_integer = _encode_der_sequence(b"\x04\x01\x17" + _encode_der_int(5))
    with pytest.raises(DHParameterError, match="expected INTEGERs"):
        parse_pkcs3_der(non_integer)

    one_int = _encode_der_sequence(_encode_der_int(23))
    with pytest.raises(DHParameterError, match="expected p, g"):
        parse_pkcs3_der(one_int)

    four_ints = _encode_der_sequence(
        _encode_der_int(23)
        + _encode_der_int(5)
        + _encode_der_int(128)
        + _encode_der_int(64)
    )
    with pytest.raises(DHParameterError, match="expected p, g"):
        parse_pkcs3_der(four_ints)


def test_load_params_from_bytes_pkcs3_pem() -> None:
    """Tests loading DH parameters from standard PKCS#3 PEM format."""
    der = _encode_der_sequence(_encode_der_int(23) + _encode_der_int(5))
    b64 = base64.b64encode(der).decode()
    pem = (
        f"-----BEGIN DH PARAMETERS-----\n{b64}\n-----END DH PARAMETERS-----\n".encode()
    )

    params = load_params_from_bytes(pem)
    assert params.p == 23
    assert params.g == 5


def test_load_params_from_bytes_corrupted_pkcs3_der() -> None:
    """Tests that corrupted PKCS#3 DER in PEM causes DHParameterError."""
    b64 = base64.b64encode(b"invalid der sequence").decode()
    pem = (
        f"-----BEGIN DH PARAMETERS-----\n{b64}\n-----END DH PARAMETERS-----\n".encode()
    )
    with pytest.raises(DHParameterError):
        load_params_from_bytes(pem)


def test_load_params_and_keys_round_trip() -> None:
    """Tests loading parameters from generated keys and serialization roundtrips."""
    raw_params = dh.generate_parameters(generator=2, key_size=512)
    param_pem = serialize_params_pkcs3_pem(raw_params)
    loaded_params = load_params_from_bytes(param_pem)
    assert loaded_params.p == raw_params.parameter_numbers().p

    key = raw_params.generate_private_key()
    priv_pem = serialize_private_pkcs8_pem(key)
    pub_pem_from_priv = serialize_public_spki_pem(key)
    pub_pem_from_pub = serialize_public_spki_pem(key.public_key())

    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem_from_priv
    assert pub_pem_from_priv == pub_pem_from_pub

    params_from_priv = load_params_from_bytes(priv_pem)
    assert params_from_priv.p == loaded_params.p

    params_from_pub = load_params_from_bytes(pub_pem_from_priv)
    assert params_from_pub.p == loaded_params.p

    x, priv_parsed_params = load_private_from_bytes(priv_pem)
    assert x == key.private_numbers().x
    assert priv_parsed_params.p == loaded_params.p

    y, pub_parsed_params = load_peer_from_bytes(pub_pem_from_priv)
    assert y == key.public_key().public_numbers().y
    assert pub_parsed_params.p == loaded_params.p


def test_load_params_and_keys_invalid_data() -> None:
    """Tests error handling for invalid or corrupted PEM data."""
    with pytest.raises(DHParameterError, match="not usable as DH parameters"):
        load_params_from_bytes(b"corrupted parameter pem content")

    with pytest.raises(DHKeyError, match="not a usable DH private key"):
        load_private_from_bytes(b"corrupted private key pem content")

    with pytest.raises(DHKeyError, match="not a usable DH public key"):
        load_peer_from_bytes(b"corrupted public key pem content")


def test_parse_secret_bytes_formats() -> None:
    """Tests decoding secret bytes as hex strings and untouched binary buffers."""
    hex_input = b"  deadbeef0102 \n"
    assert parse_secret_bytes(hex_input) == bytes.fromhex("deadbeef0102")

    invalid_hex = b"invalid_hex_string"
    assert parse_secret_bytes(invalid_hex) == invalid_hex

    raw_binary = b"\xff\xfe\x00\x01\x88"
    assert parse_secret_bytes(raw_binary) == raw_binary
