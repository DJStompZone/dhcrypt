"""Unit and integration tests for command-line interface execution and subcommands."""

from pathlib import Path
import runpy
import sys
import pytest
from dhcrypt.cli import main


def test_cli_end_to_end_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests complete CLI workflow through all subcommands and verifies roundtrip encryption."""
    params_path = tmp_path / "dhp.pem"
    alice_priv = tmp_path / "alice.pem"
    alice_pub = tmp_path / "alice.pub.pem"
    bob_priv = tmp_path / "bob.pem"
    bob_pub = tmp_path / "bob.pub.pem"
    secret_bin = tmp_path / "secret.bin"
    secret_hex = tmp_path / "secret.hex"
    plain_txt = tmp_path / "msg.txt"
    cipher_bin = tmp_path / "msg.bin"
    decrypted_txt = tmp_path / "recovered.txt"

    plain_txt.write_bytes(b"Top secret end-to-end payload message")

    rc = main(["genparams", "--bits", "512", "-o", str(params_path)])
    assert rc == 0
    assert params_path.exists()

    rc = main([
        "keygen",
        "-p", str(params_path),
        "--priv", str(alice_priv),
        "--pub", str(alice_pub),
        "--private-length", "128",
    ])
    assert rc == 0
    assert alice_priv.exists()
    assert alice_pub.exists()

    rc = main([
        "keygen",
        "-p", str(params_path),
        "--priv", str(bob_priv),
        "--pub", str(bob_pub),
    ])
    assert rc == 0

    rc_fail = main([
        "keygen",
        "-p", str(params_path),
        "--priv", str(alice_priv),
        "--pub", str(alice_pub),
    ])
    assert rc_fail == 1

    rc_force = main([
        "keygen",
        "-p", str(params_path),
        "--priv", str(alice_priv),
        "--pub", str(alice_pub),
        "--force",
    ])
    assert rc_force == 0

    rc = main([
        "derive",
        "--priv", str(alice_priv),
        "--peer", str(bob_pub),
        "--fingerprint",
        "-o", str(secret_bin),
    ])
    assert rc == 0
    assert secret_bin.exists()

    rc = main([
        "derive",
        "--priv", str(alice_priv),
        "--peer", str(bob_pub),
        "--hex",
        "-o", str(secret_hex),
    ])
    assert rc == 0
    assert secret_hex.exists()

    rc = main([
        "derive",
        "--priv", str(alice_priv),
        "--peer", str(bob_pub),
        "--strip-zeros",
        "-o", str(tmp_path / "secret_stripped.bin"),
    ])
    assert rc == 0

    rc = main([
        "encrypt",
        "--priv", str(alice_priv),
        "--peer", str(bob_pub),
        "-p", str(plain_txt),
        "-o", str(cipher_bin),
    ])
    assert rc == 0

    rc = main([
        "decrypt",
        "--priv", str(bob_priv),
        "--peer", str(alice_pub),
        "-p", str(cipher_bin),
        "-o", str(decrypted_txt),
    ])
    assert rc == 0
    assert decrypted_txt.read_bytes() == plain_txt.read_bytes()

    rc = main([
        "encrypt",
        "-k", str(secret_bin),
        "-p", str(plain_txt),
        "-o", str(cipher_bin),
    ])
    assert rc == 0

    rc = main([
        "decrypt",
        "-k", str(secret_hex),
        "-p", str(cipher_bin),
        "-o", str(decrypted_txt),
    ])
    assert rc == 0
    assert decrypted_txt.read_bytes() == plain_txt.read_bytes()


def test_cli_derive_terminal_safety(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies refusal to dump raw secrets to a terminal."""
    params_path = tmp_path / "dhp.pem"
    alice_priv = tmp_path / "alice.pem"
    alice_pub = tmp_path / "alice.pub.pem"

    main(["genparams", "--bits", "512", "-o", str(params_path)])
    main(["keygen", "-p", str(params_path), "--priv", str(alice_priv), "--pub", str(alice_pub)])

    class TtyStdout:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdout", TtyStdout())
    rc = main(["derive", "--priv", str(alice_priv), "--peer", str(alice_pub), "-o", "-"])
    assert rc == 1


def test_cli_crypt_corrupted_payload(tmp_path: Path) -> None:
    """Tests that corrupt ciphertext causes decryption command to return exit code 1."""
    secret_file = tmp_path / "secret.bin"
    corrupt_file = tmp_path / "corrupt.bin"
    secret_file.write_bytes(b"\x00" * 32)
    corrupt_file.write_bytes(b"\x00" * 40)

    rc = main(["decrypt", "-k", str(secret_file), "-p", str(corrupt_file), "-o", "-"])
    assert rc == 1


def test_cli_argument_validation_errors() -> None:
    """Tests argparse error triggering when mutual exclusivity constraints are violated."""
    with pytest.raises(SystemExit):
        main(["encrypt", "-p", "data.txt"])

    with pytest.raises(SystemExit):
        main(["encrypt", "-k", "key.bin", "--priv", "priv.pem", "-p", "data.txt"])

    with pytest.raises(SystemExit):
        main(["encrypt", "--priv", "priv.pem", "-p", "data.txt"])


def test_cli_default_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests invocation of main() when argv is None (reading from sys.argv)."""
    monkeypatch.setattr("sys.argv", ["dhcrypt", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_main_module_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests running dhcrypt as a module via runpy."""
    monkeypatch.setattr("sys.argv", ["dhcrypt", "--help"])
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("dhcrypt", run_name="__main__")
    assert exc_info.value.code == 0
