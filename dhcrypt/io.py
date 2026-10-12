"""Input/output utilities for safe file and stream handling."""

import os
import sys
from pathlib import Path
from dhcrypt.exceptions import DHIOError


def read_bytes(spec: str | Path) -> bytes:
    """Reads bytes from a file path or standard input.

    When spec is '-', data is read from standard input.

    Args:
        spec: File path string or Path object, or '-' for stdin.

    Returns:
        Bytes read from the specified source.

    Raises:
        DHIOError: If reading fails due to OS or permission errors.
    """
    path_str = str(spec)
    if path_str == "-":
        try:
            return sys.stdin.buffer.read()
        except OSError as exc:
            raise DHIOError(f"cannot read from stdin: {exc.strerror}") from exc
    try:
        return Path(spec).read_bytes()
    except OSError as exc:
        raise DHIOError(f"cannot read {spec}: {exc.strerror}") from exc


def write_bytes(spec: str | Path, data: bytes) -> None:
    """Writes bytes to a file path or standard output.

    When spec is '-', data is written to standard output and flushed.

    Args:
        spec: File path string or Path object, or '-' for stdout.
        data: Raw bytes to write.

    Raises:
        DHIOError: If writing fails due to OS or permission errors.
    """
    path_str = str(spec)
    if path_str == "-":
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            return
        except OSError as exc:
            raise DHIOError(f"cannot write to stdout: {exc.strerror}") from exc
    try:
        Path(spec).write_bytes(data)
    except OSError as exc:
        raise DHIOError(f"cannot write {spec}: {exc.strerror}") from exc


def write_private(spec: str | Path, data: bytes, force: bool = False) -> None:
    """Writes private key bytes with restrictive 0600 permissions.

    Refuses to overwrite existing files unless forced.

    Args:
        spec: Destination file path.
        data: Private key bytes to write.
        force: If True, allows overwriting existing destination files.

    Raises:
        DHIOError: If destination exists without force, or if an OS error occurs.
    """
    path_str = str(spec)
    if path_str == "-":
        write_bytes(path_str, data)
        return
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        descriptor = os.open(path_str, flags, 0o600)
    except FileExistsError as exc:
        raise DHIOError(f"{spec} already exists (use --force to overwrite)") from exc
    except OSError as exc:
        raise DHIOError(f"cannot write {spec}: {exc.strerror}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        raise DHIOError(f"cannot write {spec}: {exc.strerror}") from exc
