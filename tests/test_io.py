"""Unit tests for file and stream I/O routines."""

import io
import os
from pathlib import Path
from typing import Any
import pytest
from dhcrypt.exceptions import DHIOError
from dhcrypt.io import read_bytes, write_bytes, write_private


class FakeBufferStream:
    """Helper mock stream providing a buffer property for stdin/stdout testing."""

    def __init__(self, buffer: io.BytesIO) -> None:
        """Initializes mock stream with internal buffer.

        Args:
            buffer: io.BytesIO buffer instance.
        """
        self.buffer = buffer

    def isatty(self) -> bool:
        """Indicates whether stream is a terminal."""
        return False


def test_read_bytes_from_file_and_missing(tmp_path: Path) -> None:
    """Tests reading bytes from an existing file and handling missing files."""
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"hello file io")

    assert read_bytes(test_file) == b"hello file io"

    missing_file = tmp_path / "nonexistent.txt"
    with pytest.raises(DHIOError, match="cannot read"):
        read_bytes(missing_file)


def test_read_bytes_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests reading bytes from standard input stream."""
    buffer = io.BytesIO(b"stdin content")
    monkeypatch.setattr("sys.stdin", FakeBufferStream(buffer))

    assert read_bytes("-") == b"stdin content"


def test_read_bytes_stdin_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that OSError on standard input is converted to DHIOError."""
    class BrokenStdin:
        def read(self) -> bytes:
            raise OSError("stdin broken")

    monkeypatch.setattr("sys.stdin", type("StdinWrapper", (), {"buffer": BrokenStdin()})())

    with pytest.raises(DHIOError, match="cannot read from stdin"):
        read_bytes("-")


def test_write_bytes_to_file_and_error(tmp_path: Path) -> None:
    """Tests writing bytes to a file path and handling unwritable paths."""
    out_file = tmp_path / "output.bin"
    write_bytes(out_file, b"binary data")
    assert out_file.read_bytes() == b"binary data"

    invalid_path = tmp_path / "nonexistent_dir" / "file.bin"
    with pytest.raises(DHIOError, match="cannot write"):
        write_bytes(invalid_path, b"data")


def test_write_bytes_to_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests writing bytes to standard output buffer."""
    buffer = io.BytesIO()
    monkeypatch.setattr("sys.stdout", FakeBufferStream(buffer))

    write_bytes("-", b"stdout stream content")
    assert buffer.getvalue() == b"stdout stream content"


def test_write_bytes_stdout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that OSError on standard output is converted to DHIOError."""
    class BrokenStdout:
        def write(self, data: bytes) -> int:
            raise OSError("stdout broken")

        def flush(self) -> None:
            pass

    monkeypatch.setattr("sys.stdout", type("StdoutWrapper", (), {"buffer": BrokenStdout()})())

    with pytest.raises(DHIOError, match="cannot write to stdout"):
        write_bytes("-", b"payload")


def test_write_private_mode_and_overwrite(tmp_path: Path) -> None:
    """Tests writing private key files with overwrite restrictions."""
    key_path = tmp_path / "private.pem"
    write_private(key_path, b"secret private key", force=False)
    assert key_path.read_bytes() == b"secret private key"

    with pytest.raises(DHIOError, match="already exists"):
        write_private(key_path, b"new content", force=False)

    write_private(key_path, b"overwritten content", force=True)
    assert key_path.read_bytes() == b"overwritten content"


def test_write_private_to_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests writing private key to stdout when spec is '-'."""
    buffer = io.BytesIO()
    monkeypatch.setattr("sys.stdout", FakeBufferStream(buffer))

    write_private("-", b"key to stdout")
    assert buffer.getvalue() == b"key to stdout"


def test_write_private_os_error(tmp_path: Path) -> None:
    """Verifies that OSError when opening private key file raises DHIOError."""
    invalid_path = tmp_path / "no_dir" / "key.pem"
    with pytest.raises(DHIOError, match="cannot write"):
        write_private(invalid_path, b"secret")


def test_write_private_fdopen_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies that an OSError during fdopen or writing raises DHIOError."""
    key_path = tmp_path / "private.pem"

    def fail_fdopen(descriptor: int, mode: str) -> Any:
        os.close(descriptor)
        raise OSError("write failed")

    monkeypatch.setattr("os.fdopen", fail_fdopen)
    with pytest.raises(DHIOError, match="cannot write"):
        write_private(key_path, b"data")
