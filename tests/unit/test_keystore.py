import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from securedocs_worker.keystore import load_or_generate_signing_key


def test_generates_keypair_when_absent(tmp_path: Path) -> None:
    private_path = tmp_path / "keys" / "ed25519.private"
    public_path = tmp_path / "keys" / "ed25519.public"

    key = load_or_generate_signing_key(private_path, public_path)

    assert isinstance(key, Ed25519PrivateKey)
    assert private_path.exists()
    assert public_path.exists()


def test_generated_private_key_is_owner_only(tmp_path: Path) -> None:
    private_path = tmp_path / "ed25519.private"
    public_path = tmp_path / "ed25519.public"

    load_or_generate_signing_key(private_path, public_path)

    mode = stat.S_IMODE(private_path.stat().st_mode)
    assert mode == 0o600


def test_loads_existing_key_and_round_trips(tmp_path: Path) -> None:
    private_path = tmp_path / "ed25519.private"
    public_path = tmp_path / "ed25519.public"

    generated = load_or_generate_signing_key(private_path, public_path)
    loaded = load_or_generate_signing_key(private_path, public_path)

    message = b"sign me"
    signature = generated.sign(message)
    # The reloaded key's public half verifies a signature from the original.
    loaded.public_key().verify(signature, message)


def test_does_not_regenerate_when_key_exists(tmp_path: Path) -> None:
    private_path = tmp_path / "ed25519.private"
    public_path = tmp_path / "ed25519.public"

    first = load_or_generate_signing_key(private_path, public_path)
    second = load_or_generate_signing_key(private_path, public_path)

    assert first.private_bytes_raw() == second.private_bytes_raw()


def test_raises_when_existing_key_is_wrong_type(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization

    private_path = tmp_path / "rsa.private"
    public_path = tmp_path / "rsa.public"

    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_path.write_bytes(
        rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    with pytest.raises(TypeError):
        load_or_generate_signing_key(private_path, public_path)
