import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SHA256_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64
AES_256_KEY_LENGTH = 32
AES_GCM_NONCE_LENGTH = 12
SALT_LENGTH = 16


@dataclass(frozen=True)
class ScryptParameters:
    n: int = 16384
    r: int = 8
    p: int = 1


@dataclass(frozen=True)
class EncryptedBlob:
    ciphertext: bytes
    nonce: bytes
    tag: bytes


def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def generate_nonce() -> bytes:
    return os.urandom(AES_GCM_NONCE_LENGTH)


def compute_hash(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def derive_key(passphrase: str, salt: bytes, params: ScryptParameters) -> bytes:
    scrypt = Scrypt(
        salt=salt,
        length=AES_256_KEY_LENGTH,
        n=params.n,
        r=params.r,
        p=params.p,
    )
    return scrypt.derive(passphrase.encode("utf-8"))


def encrypt_aes_gcm(key: bytes, plaintext: bytes, nonce: bytes) -> EncryptedBlob:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return EncryptedBlob(ciphertext=ciphertext, nonce=nonce, tag=encryptor.tag)


def sign_ed25519(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)
