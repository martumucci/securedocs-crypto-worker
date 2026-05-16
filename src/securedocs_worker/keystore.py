from pathlib import Path

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = structlog.get_logger().bind(logger=__name__)


def load_or_generate_signing_key(
    private_key_path: Path,
    public_key_path: Path,
) -> Ed25519PrivateKey:
    if private_key_path.exists():
        return _load_private_key(private_key_path)
    return _generate_and_persist(private_key_path, public_key_path)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(
            f"Expected an Ed25519 private key at {path}, got {type(key).__name__}"
        )
    return key


def _generate_and_persist(
    private_key_path: Path,
    public_key_path: Path,
) -> Ed25519PrivateKey:
    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(private_pem)
    private_key_path.chmod(0o600)

    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(public_pem)

    logger.info("generated new Ed25519 keypair", path=str(private_key_path))
    return private_key
