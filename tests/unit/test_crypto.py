from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from securedocs_worker.crypto import (
    AES_256_KEY_LENGTH,
    AES_GCM_NONCE_LENGTH,
    ED25519_SIGNATURE_LENGTH,
    SALT_LENGTH,
    SHA256_LENGTH,
    ScryptParameters,
    compute_hash,
    derive_key,
    encrypt_aes_gcm,
    generate_nonce,
    generate_salt,
    sign_ed25519,
)


def test_generate_salt_returns_expected_length() -> None:
    salt = generate_salt()

    assert len(salt) == SALT_LENGTH


def test_generate_salt_is_random() -> None:
    assert generate_salt() != generate_salt()


def test_generate_nonce_returns_expected_length() -> None:
    nonce = generate_nonce()

    assert len(nonce) == AES_GCM_NONCE_LENGTH


def test_generate_nonce_is_random() -> None:
    assert generate_nonce() != generate_nonce()


def test_compute_hash_returns_expected_length() -> None:
    digest = compute_hash(b"any content")

    assert len(digest) == SHA256_LENGTH


def test_compute_hash_is_deterministic() -> None:
    assert compute_hash(b"identical") == compute_hash(b"identical")


def test_compute_hash_differs_for_different_inputs() -> None:
    assert compute_hash(b"one") != compute_hash(b"two")


def test_compute_hash_matches_known_vector() -> None:
    # SHA-256("abc") — NIST FIPS 180-4 test vector
    expected = bytes.fromhex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert compute_hash(b"abc") == expected


def test_derive_key_returns_expected_length() -> None:
    key = derive_key("any passphrase", generate_salt(), ScryptParameters())

    assert len(key) == AES_256_KEY_LENGTH


def test_derive_key_is_deterministic_for_same_inputs() -> None:
    salt = generate_salt()
    params = ScryptParameters()

    first = derive_key("same passphrase", salt, params)
    second = derive_key("same passphrase", salt, params)

    assert first == second


def test_derive_key_differs_for_different_passphrases() -> None:
    salt = generate_salt()
    params = ScryptParameters()

    assert derive_key("one", salt, params) != derive_key("two", salt, params)


def test_derive_key_differs_for_different_salts() -> None:
    params = ScryptParameters()

    assert derive_key("same", generate_salt(), params) != derive_key(
        "same", generate_salt(), params
    )


def test_encrypt_aes_gcm_round_trips_to_original_plaintext() -> None:
    key = derive_key("test passphrase", generate_salt(), ScryptParameters())
    nonce = generate_nonce()
    plaintext = b"secret content"

    blob = encrypt_aes_gcm(key, plaintext, nonce)

    decryptor = Cipher(algorithms.AES(key), modes.GCM(blob.nonce, blob.tag)).decryptor()
    recovered = decryptor.update(blob.ciphertext) + decryptor.finalize()

    assert recovered == plaintext


def test_encrypt_aes_gcm_preserves_nonce_in_output() -> None:
    key = derive_key("any", generate_salt(), ScryptParameters())
    nonce = generate_nonce()

    blob = encrypt_aes_gcm(key, b"content", nonce)

    assert blob.nonce == nonce


def test_encrypt_aes_gcm_tag_is_16_bytes() -> None:
    key = derive_key("any", generate_salt(), ScryptParameters())

    blob = encrypt_aes_gcm(key, b"content", generate_nonce())

    assert len(blob.tag) == 16


def test_sign_ed25519_returns_expected_length() -> None:
    private_key = Ed25519PrivateKey.generate()

    signature = sign_ed25519(private_key, b"any message")

    assert len(signature) == ED25519_SIGNATURE_LENGTH


def test_sign_ed25519_signature_verifies_with_public_key() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    message = b"message to sign"

    signature = sign_ed25519(private_key, message)

    public_key.verify(signature, message)  # raises InvalidSignature if invalid


def test_sign_ed25519_signature_fails_for_tampered_message() -> None:
    import pytest

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    signature = sign_ed25519(private_key, b"original")

    with pytest.raises(InvalidSignature):
        public_key.verify(signature, b"tampered")
