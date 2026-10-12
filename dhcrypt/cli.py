"""Command-line interface argument parsing and command dispatching."""

import argparse
import sys
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from cryptography.hazmat.primitives import hashes
from dhcrypt.exceptions import DHError
from dhcrypt.io import read_bytes, write_bytes, write_private
from dhcrypt.serialization import parse_secret_bytes
from dhcrypt.service import (
    decrypt_message,
    derive_shared_secret,
    encrypt_message,
    generate_keypair_pem,
    generate_parameters_pem,
)


def run_genparams(args: argparse.Namespace) -> None:
    """Executes the genparams command to generate PKCS#3 parameters.

    Args:
        args: Parsed CLI arguments containing bits and output path.
    """
    sys.stderr.write(
        f"Generating {args.bits}-bit safe-prime parameters (can be slow)...\n"
    )
    pem = generate_parameters_pem(key_size=args.bits)
    write_bytes(args.out, pem)


def run_keygen(args: argparse.Namespace) -> None:
    """Executes the keygen command to generate a keypair from parameters.

    Args:
        args: Parsed CLI arguments containing params, priv, pub, private_length, and force.
    """
    params_data = read_bytes(args.params)
    priv_pem, pub_pem, bits = generate_keypair_pem(
        params_data, private_length=args.private_length
    )
    write_private(args.priv, priv_pem, force=args.force)
    write_bytes(args.pub, pub_pem)
    sys.stderr.write(
        f"Wrote {args.priv} (mode 0600, {bits}-bit exponent) and {args.pub}\n"
    )


def run_derive(args: argparse.Namespace) -> None:
    """Executes the derive command to compute the shared secret.

    Args:
        args: Parsed CLI arguments containing priv, peer, out, hex, fingerprint, and strip_zeros.
    """
    priv_data = read_bytes(args.priv)
    peer_data = read_bytes(args.peer)
    secret = derive_shared_secret(
        priv_data, peer_data, strip_zeros=args.strip_zeros
    )
    if args.fingerprint:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(secret)
        sys.stderr.write(f"sha256(secret) = {digest.finalize().hex()}\n")
    if args.out == "-" and not args.hex and sys.stdout.isatty():
        raise DHError("refusing to dump raw secret to a terminal (use --hex or -o)")
    payload = (secret.hex() + "\n").encode() if args.hex else secret
    write_bytes(args.out, payload)


def run_crypt(args: argparse.Namespace) -> None:
    """Executes the encrypt or decrypt command.

    Args:
        args: Parsed CLI arguments specifying mode, keys, payload, and output target.
    """
    if args.pem:
        secret = parse_secret_bytes(read_bytes(args.pem))
    else:
        priv_data = read_bytes(args.priv)
        peer_data = read_bytes(args.peer)
        secret = derive_shared_secret(
            priv_data, peer_data, strip_zeros=args.strip_zeros
        )
    data = read_bytes(args.payload)
    if args.mode == "encrypt":
        result = encrypt_message(secret, data)
    else:
        result = decrypt_message(secret, data)
    write_bytes(args.out, result)


def setup_argparse() -> argparse.ArgumentParser:
    """Configures the command-line argument parser and subcommands.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="DH key exchange + AES-256-GCM, OpenSSL-compatible, in one tool."
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    gp = sub.add_parser("genparams", help="generate DH parameters (PKCS#3 PEM)")
    gp.add_argument(
        "--bits", type=int, default=2048, help="prime size (default 2048)"
    )
    gp.add_argument("-o", "--out", default="-", help="output file (default stdout)")
    gp.set_defaults(func=run_genparams)

    kg = sub.add_parser("keygen", help="generate a DH keypair from parameters")
    kg.add_argument(
        "-p",
        "--params",
        required=True,
        help="DH parameters PEM (or any DH key PEM carrying them)",
    )
    kg.add_argument(
        "--priv", required=True, help="private key output (PKCS#8, mode 0600)"
    )
    kg.add_argument("--pub", required=True, help="public key output (SPKI PEM)")
    kg.add_argument(
        "--private-length",
        type=int,
        help="private exponent size in bits (default: from params, else full size)",
    )
    kg.add_argument(
        "--force", action="store_true", help="overwrite an existing private key"
    )
    kg.set_defaults(func=run_keygen)

    dv = sub.add_parser("derive", help="derive the raw shared secret")
    dv.add_argument("--priv", required=True, help="our private key PEM")
    dv.add_argument("--peer", required=True, help="their public key PEM")
    dv.add_argument("-o", "--out", default="-", help="output file (default stdout)")
    dv.add_argument("--hex", action="store_true", help="write the secret as hex text")
    dv.add_argument(
        "--fingerprint",
        action="store_true",
        help="print sha256(secret) to stderr for out-of-band comparison",
    )
    dv.add_argument(
        "--strip-zeros",
        action="store_true",
        help="drop leading zero bytes (legacy OpenSSL 1.x behavior)",
    )
    dv.set_defaults(func=run_derive)

    for name, helptext in (
        ("encrypt", "encrypt a payload"),
        ("decrypt", "decrypt a payload"),
    ):
        sp = sub.add_parser(name, help=helptext)
        group = sp.add_argument_group("secret (pick one)")
        group.add_argument(
            "-k",
            "--pem",
            help="file holding the shared secret (raw bytes or hex)",
        )
        group.add_argument("--priv", help="our private key PEM (use with --peer)")
        group.add_argument("--peer", help="their public key PEM (use with --priv)")
        sp.add_argument(
            "--strip-zeros",
            action="store_true",
            help="legacy OpenSSL 1.x secret padding (with --priv/--peer)",
        )
        sp.add_argument(
            "-p", "--payload", required=True, help="input file ('-' for stdin)"
        )
        sp.add_argument("-o", "--out", default="-", help="output file (default stdout)")
        sp.set_defaults(func=run_crypt, mode=name)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint.

    Parses command-line arguments, validates mutual exclusivity, executes
    requested handler, and handles exceptions cleanly.

    Args:
        argv: Optional argument vector. If None, sys.argv[1:] is used.

    Returns:
        Exit code integer (0 on success, non-zero on failure).
    """
    parser = setup_argparse()
    args = parser.parse_args(argv)
    if args.mode in ("encrypt", "decrypt"):
        if bool(args.pem) == bool(args.priv or args.peer):
            parser.error("give either -k/--pem, or both --priv and --peer")
        if not args.pem and not (args.priv and args.peer):
            parser.error("--priv and --peer must be used together")
    try:
        args.func(args)
        return 0
    except DHError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
