#!/usr/bin/env python3
"""
Baby's first AES-GCM encryption CLI utilizing a derived symmetric (DH) key.

(Adorable and effective ¹)

   DJ Stomp 2026
"No Rights Reserved"
    MIT License ²


¹ (Citation needed)
² https://opensource.org/license/mit

All-in-one edition: DH parameter generation, keygen, key agreement, and
AES-256-GCM encrypt/decrypt, all in Python and interoperable with OpenSSL
(`openssl genpkey -paramfile`, `openssl pkeyutl -derive`, ...).

    dhcrypt.py genparams --bits 2048 -o dhp.pem
    dhcrypt.py keygen -p dhp.pem --priv me.pem --pub me.pub.pem
    dhcrypt.py derive --priv me.pem --peer them.pub.pem --fingerprint -o secret.bin
    dhcrypt.py encrypt --priv me.pem --peer them.pub.pem -p msg.txt -o msg.bin
    dhcrypt.py decrypt -k secret.bin -p msg.bin
"""

import argparse
import base64
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"stompzone-dh-kex-context"


class DHError(Exception):
    """A user-facing failure (bad input, mismatched parameters, ...)."""


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #

def read_bytes(spec: str) -> bytes:
    """Reads a file, or stdin when spec is '-'."""
    if spec == "-":
        return sys.stdin.buffer.read()
    try:
        return Path(spec).read_bytes()
    except OSError as exc:
        raise DHError(f"cannot read {spec}: {exc.strerror}") from exc


def write_bytes(spec: str, data: bytes) -> None:
    """Writes a file, or stdout when spec is '-'."""
    if spec == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    try:
        Path(spec).write_bytes(data)
    except OSError as exc:
        raise DHError(f"cannot write {spec}: {exc.strerror}") from exc


def write_private(spec: str, data: bytes, force: bool) -> None:
    """Writes a private key with mode 0600, refusing to clobber unless forced."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        fd = os.open(spec, flags, 0o600)
    except FileExistsError as exc:
        raise DHError(f"{spec} already exists (use --force to overwrite)") from exc
    except OSError as exc:
        raise DHError(f"cannot write {spec}: {exc.strerror}") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


# --------------------------------------------------------------------------- #
# OpenSSL-compat layer
#
# `cryptography` misreads the optional privateValueLength of a PKCS#3 "DH
# PARAMETERS" file (which `openssl genpkey -genparam` writes) as the subgroup
# order q, after which generate_private_key() fails with an opaque BN error.
# We parse PKCS#3 ourselves and generate the private exponent the way OpenSSL
# does, honoring that length, and do the modexp ourselves so the secret is
# padded to len(p) exactly like OpenSSL 3.x.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DHParams:
    p: int
    g: int
    length: int | None = None  # OpenSSL's privateValueLength, in bits

    def numbers(self) -> dh.DHParameterNumbers:
        return dh.DHParameterNumbers(self.p, self.g)


def _der_read(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Reads one DER TLV header; returns (tag, content_start, content_end)."""
    try:
        tag = buf[pos]
        size = buf[pos + 1]
        pos += 2
        if size & 0x80:
            count = size & 0x7F
            size = int.from_bytes(buf[pos:pos + count], "big")
            pos += count
    except IndexError as exc:
        raise DHError("truncated DH parameters") from exc
    if pos + size > len(buf):
        raise DHError("truncated DH parameters")
    return tag, pos, pos + size


def parse_pkcs3(der: bytes) -> DHParams:
    """Parses PKCS#3 DHParameter ::= SEQUENCE { p, g, privateValueLength OPTIONAL }."""
    tag, pos, end = _der_read(der, 0)
    if tag != 0x30:
        raise DHError("DH parameters: expected a SEQUENCE")
    ints = []
    while pos < end:
        tag, start, stop = _der_read(der, pos)
        if tag != 0x02:
            raise DHError("DH parameters: expected INTEGERs")
        ints.append(int.from_bytes(der[start:stop], "big"))
        pos = stop
    if len(ints) not in (2, 3):
        raise DHError("DH parameters: expected p, g[, privateValueLength]")
    return DHParams(ints[0], ints[1], ints[2] if len(ints) == 3 else None)


def load_params(path: str) -> DHParams:
    """Loads params from a 'DH PARAMETERS' PEM, or from any DH key PEM."""
    data = read_bytes(path)
    text = data.decode("ascii", errors="ignore")
    marker = "-----BEGIN DH PARAMETERS-----"
    try:
        if marker in text:
            body = text.split(marker, 1)[1].split("-----END", 1)[0]
            return parse_pkcs3(base64.b64decode("".join(body.split())))
        if "PRIVATE KEY" in text:
            key = serialization.load_pem_private_key(data, None)
            nums = key.parameters().parameter_numbers()  # type: ignore[union-attr]
        elif "PUBLIC KEY" in text:
            key = serialization.load_pem_public_key(data)
            nums = key.parameters().parameter_numbers()  # type: ignore[union-attr]
        else:
            nums = serialization.load_pem_parameters(data).parameter_numbers()
    except DHError:
        raise
    except Exception as exc:  # cryptography raises a zoo of types here
        raise DHError(f"{path}: not usable as DH parameters ({exc})") from exc
    return DHParams(nums.p, nums.g)


def load_private(path: str) -> tuple[int, DHParams]:
    """Loads a DH private key (PKCS#8 or traditional); returns (x, params)."""
    try:
        key = serialization.load_pem_private_key(read_bytes(path), None)
        numbers = key.private_numbers()  # type: ignore[union-attr]
        pn = numbers.public_numbers.parameter_numbers
    except DHError:
        raise
    except Exception as exc:
        raise DHError(f"{path}: not a usable DH private key ({exc})") from exc
    return numbers.x, DHParams(pn.p, pn.g)


def load_peer(path: str) -> tuple[int, DHParams]:
    """Loads a peer's DH public key; returns (y, params)."""
    try:
        key = serialization.load_pem_public_key(read_bytes(path))
        numbers = key.public_numbers()  # type: ignore[union-attr]
        pn = numbers.parameter_numbers
    except DHError:
        raise
    except Exception as exc:
        raise DHError(f"{path}: not a usable DH public key ({exc})") from exc
    return numbers.y, DHParams(pn.p, pn.g)


def generate_private(params: DHParams) -> dh.DHPrivateKey:
    """Generates a private key the way OpenSSL does for these params."""
    if params.length is None:
        # No length hint: OpenSSL picks a full-size exponent; so does cryptography.
        return params.numbers().parameters().generate_private_key()
    bits = params.length
    if not 2 <= bits < params.p.bit_length():
        raise DHError(f"private length {bits} is out of range for this prime")
    while True:
        x = secrets.randbits(bits) | (1 << (bits - 1))  # exactly `bits` bits
        if 1 < x < params.p - 1:
            break
    y = pow(params.g, x, params.p)
    return dh.DHPrivateNumbers(x, dh.DHPublicNumbers(y, params.numbers())).private_key()


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin."""
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def validate_peer_public(y: int, params: DHParams) -> None:
    """Rejects degenerate or out-of-subgroup peer public values.

    Always enforces 2 <= y <= p-2 (as OpenSSL's DH_check_pub_key does). When p
    is a safe prime and g generates the order-q subgroup, also requires
    y^q == 1 (mod p), which blocks small-subgroup confinement.
    """
    p = params.p
    if not 2 <= y <= p - 2:
        raise DHError("peer public value is out of range (possible attack)")
    q = (p - 1) // 2
    if pow(params.g, q, p) == 1 and is_probable_prime(q) and pow(y, q, p) != 1:
        raise DHError("peer public value is not in the prime-order subgroup")


def compute_shared(x: int, y: int, params: DHParams, strip_zeros: bool = False) -> bytes:
    """Raw DH shared secret, padded to len(p) like OpenSSL 3.x.

    strip_zeros=True reproduces the legacy OpenSSL 1.x / DH_compute_key
    behavior of dropping leading zero bytes.
    """
    validate_peer_public(y, params)
    z = pow(y, x, params.p)
    if z in (0, 1, params.p - 1):
        raise DHError("degenerate shared secret")
    size = (z.bit_length() + 7) // 8 if strip_zeros else (params.p.bit_length() + 7) // 8
    return z.to_bytes(size, "big")


def shared_from_files(priv_path: str, peer_path: str, strip_zeros: bool = False) -> bytes:
    """Derives the raw shared secret from our private key and their public key."""
    x, ours = load_private(priv_path)
    y, theirs = load_peer(peer_path)
    if (ours.p, ours.g) != (theirs.p, theirs.g):
        raise DHError("private key and peer public key use different DH parameters")
    return compute_shared(x, y, ours, strip_zeros)


# --------------------------------------------------------------------------- #
# Symmetric layer (unchanged wire format: nonce(12) || ciphertext || tag(16))
# --------------------------------------------------------------------------- #

def derive_symmetric_key(shared_secret: bytes, salt: bytes | None = None) -> bytes:
    """Derives a 256-bit symmetric key from a raw shared secret using HKDF.

    Args:
        shared_secret: The raw bytes obtained from a key exchange.
        salt: Optional cryptographic salt. Should be shared publicly if used.

    Returns:
        A 32-byte symmetric key suitable for AES-256.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO)
    return hkdf.derive(shared_secret)


def encrypt_payload(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts a plaintext payload using AES-256-GCM; returns nonce + ciphertext."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_payload(key: bytes, encrypted_payload: bytes) -> bytes:
    """Decrypts a nonce + ciphertext payload produced by encrypt_payload."""
    if len(encrypted_payload) < 12 + 16:
        raise DHError("payload is too short to be valid")
    return AESGCM(key).decrypt(encrypted_payload[:12], encrypted_payload[12:], None)


def parse_secret(data: bytes) -> bytes:
    """Interprets a secret file as a hex string or as raw bytes.

    Surrounding whitespace is tolerated only for the hex interpretation. Raw
    bytes are returned untouched, since stripping would corrupt any secret that
    begins or ends with a whitespace byte.
    """
    try:
        return bytes.fromhex(data.decode("utf-8").strip())
    except (ValueError, UnicodeDecodeError):
        return data


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_genparams(args: argparse.Namespace) -> None:
    sys.stderr.write(f"Generating {args.bits}-bit safe-prime parameters (can be slow)...\n")
    params = dh.generate_parameters(generator=2, key_size=args.bits)
    pem = params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
    write_bytes(args.out, pem)


def cmd_keygen(args: argparse.Namespace) -> None:
    params = load_params(args.params)
    if args.private_length is not None:
        params = DHParams(params.p, params.g, args.private_length)
    key = generate_private(params)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    write_private(args.priv, priv, args.force)
    write_bytes(args.pub, pub)
    bits = key.private_numbers().x.bit_length()
    sys.stderr.write(f"Wrote {args.priv} (mode 0600, {bits}-bit exponent) and {args.pub}\n")


def cmd_derive(args: argparse.Namespace) -> None:
    secret = shared_from_files(args.priv, args.peer, args.strip_zeros)
    if args.fingerprint:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(secret)
        sys.stderr.write(f"sha256(secret) = {digest.finalize().hex()}\n")
    if args.out == "-" and not args.hex and sys.stdout.isatty():
        raise DHError("refusing to dump raw secret to a terminal (use --hex or -o)")
    write_bytes(args.out, (secret.hex() + "\n").encode() if args.hex else secret)


def cmd_crypt(args: argparse.Namespace) -> None:
    if args.pem:
        secret = parse_secret(read_bytes(args.pem))
    else:
        secret = shared_from_files(args.priv, args.peer, args.strip_zeros)
    key = derive_symmetric_key(secret)
    data = read_bytes(args.payload)
    if args.mode == "encrypt":
        result = encrypt_payload(key, data)
    else:
        try:
            result = decrypt_payload(key, data)
        except InvalidTag:
            raise DHError(
                "decryption failed: invalid authentication tag (wrong key or corrupted payload)"
            ) from None
    write_bytes(args.out, result)


def setup_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DH key exchange + AES-256-GCM, OpenSSL-compatible, in one tool."
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    gp = sub.add_parser("genparams", help="generate DH parameters (PKCS#3 PEM)")
    gp.add_argument("--bits", type=int, default=2048, help="prime size (default 2048)")
    gp.add_argument("-o", "--out", default="-", help="output file (default stdout)")
    gp.set_defaults(func=cmd_genparams)

    kg = sub.add_parser("keygen", help="generate a DH keypair from parameters")
    kg.add_argument("-p", "--params", required=True,
                    help="DH parameters PEM (or any DH key PEM carrying them)")
    kg.add_argument("--priv", required=True, help="private key output (PKCS#8, mode 0600)")
    kg.add_argument("--pub", required=True, help="public key output (SPKI PEM)")
    kg.add_argument("--private-length", type=int,
                    help="private exponent size in bits (default: from params, else full size)")
    kg.add_argument("--force", action="store_true", help="overwrite an existing private key")
    kg.set_defaults(func=cmd_keygen)

    dv = sub.add_parser("derive", help="derive the raw shared secret")
    dv.add_argument("--priv", required=True, help="our private key PEM")
    dv.add_argument("--peer", required=True, help="their public key PEM")
    dv.add_argument("-o", "--out", default="-", help="output file (default stdout)")
    dv.add_argument("--hex", action="store_true", help="write the secret as hex text")
    dv.add_argument("--fingerprint", action="store_true",
                    help="print sha256(secret) to stderr for out-of-band comparison")
    dv.add_argument("--strip-zeros", action="store_true",
                    help="drop leading zero bytes (legacy OpenSSL 1.x behavior)")
    dv.set_defaults(func=cmd_derive)

    for name, helptext in (("encrypt", "encrypt a payload"), ("decrypt", "decrypt a payload")):
        sp = sub.add_parser(name, help=helptext)
        group = sp.add_argument_group("secret (pick one)")
        group.add_argument("-k", "--pem", help="file holding the shared secret (raw bytes or hex)")
        group.add_argument("--priv", help="our private key PEM (use with --peer)")
        group.add_argument("--peer", help="their public key PEM (use with --priv)")
        sp.add_argument("--strip-zeros", action="store_true",
                        help="legacy OpenSSL 1.x secret padding (with --priv/--peer)")
        sp.add_argument("-p", "--payload", required=True, help="input file ('-' for stdin)")
        sp.add_argument("-o", "--out", default="-", help="output file (default stdout)")
        sp.set_defaults(func=cmd_crypt, mode=name)
    return parser


def main() -> None:
    parser = setup_argparse()
    args = parser.parse_args()
    if args.mode in ("encrypt", "decrypt"):
        if bool(args.pem) == bool(args.priv or args.peer):
            parser.error("give either -k/--pem, or both --priv and --peer")
        if not args.pem and not (args.priv and args.peer):
            parser.error("--priv and --peer must be used together")
    try:
        args.func(args)
    except DHError as exc:
        sys.stderr.write(f"error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
