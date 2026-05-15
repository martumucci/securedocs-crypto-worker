from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from securedocs_worker import crypto
from securedocs_worker.events import DocumentStatus, DocumentSubmittedEvent
from securedocs_worker.processor import DocumentProcessor, canonical_timestamp
from securedocs_worker.rabbitmq import MassTransitPublisher
from securedocs_worker.redis_store import RedisPayloadStore, SubmissionPayload

DOCUMENT_ID = UUID("22222222-2222-2222-2222-222222222222")
PASSPHRASE = "correct horse battery staple"
PLAINTEXT = "sensitive legal document content"

# Low scrypt cost so tests stay fast.
TEST_SCRYPT = crypto.ScryptParameters(n=1024, r=8, p=1)


def _submitted_event() -> DocumentSubmittedEvent:
    return DocumentSubmittedEvent(
        message_id=UUID("11111111-1111-1111-1111-111111111111"),
        document_id=DOCUMENT_ID,
        submitted_at=datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_processor() -> tuple[DocumentProcessor, Mock, Mock, Ed25519PrivateKey]:
    redis = Mock(spec=RedisPayloadStore)
    publisher = Mock(spec=MassTransitPublisher)
    signing_key = Ed25519PrivateKey.generate()
    processor = DocumentProcessor(
        redis_store=redis,
        publisher=publisher,
        signing_key=signing_key,
        scrypt_params=TEST_SCRYPT,
    )
    return processor, redis, publisher, signing_key


class TestCanonicalTimestamp:
    def test_formats_with_millisecond_precision_and_z_suffix(self) -> None:
        dt = datetime(2026, 5, 15, 12, 34, 56, 789000, tzinfo=timezone.utc)

        assert canonical_timestamp(dt) == "2026-05-15T12:34:56.789Z"

    def test_zero_microseconds_formats_as_000(self) -> None:
        dt = datetime(2026, 5, 15, 12, 34, 56, 0, tzinfo=timezone.utc)

        assert canonical_timestamp(dt) == "2026-05-15T12:34:56.000Z"

    def test_converts_non_utc_to_utc(self) -> None:
        tz = timezone(timedelta(hours=-3))
        dt = datetime(2026, 5, 15, 9, 0, 0, tzinfo=tz)

        assert canonical_timestamp(dt) == "2026-05-15T12:00:00.000Z"


class TestProcessSuccess:
    def test_publishes_success_event_and_deletes_redis_key(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)

        processor.process(_submitted_event())

        publisher.publish.assert_called_once()
        published_event = publisher.publish.call_args[0][0]
        assert published_event.status == DocumentStatus.Success
        assert published_event.document_id == DOCUMENT_ID
        redis.delete.assert_called_once_with(DOCUMENT_ID)

    def test_published_hash_matches_sha256_of_plaintext(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)

        processor.process(_submitted_event())

        event = publisher.publish.call_args[0][0]
        assert event.hash == crypto.compute_hash(PLAINTEXT.encode("utf-8"))

    def test_signature_verifies_against_public_key(self) -> None:
        processor, redis, publisher, signing_key = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)

        processor.process(_submitted_event())

        event = publisher.publish.call_args[0][0]
        signed_message = event.hash + canonical_timestamp(event.processed_at).encode("utf-8")
        # raises InvalidSignature if the signature does not verify
        signing_key.public_key().verify(event.signature, signed_message)

    def test_ciphertext_decrypts_back_to_plaintext(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)

        processor.process(_submitted_event())

        event = publisher.publish.call_args[0][0]
        key = crypto.derive_key(PASSPHRASE, event.salt, TEST_SCRYPT)
        decryptor = Cipher(
            algorithms.AES(key), modes.GCM(event.nonce, event.tag)
        ).decryptor()
        recovered = decryptor.update(event.ciphertext) + decryptor.finalize()

        assert recovered.decode("utf-8") == PLAINTEXT

    def test_kdf_metadata_reflects_scrypt_params(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)

        processor.process(_submitted_event())

        event = publisher.publish.call_args[0][0]
        assert event.kdf_algorithm == "scrypt"
        assert event.kdf_parameters == '{"n":1024,"r":8,"p":1}'
        assert event.algorithm == "AES-256-GCM"

    def test_propagates_correlation_id_to_publisher(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)

        processor.process(_submitted_event(), correlation_id="trace-99")

        assert publisher.publish.call_args[0][1] == "trace-99"


class TestProcessFailure:
    def test_payload_not_available_publishes_failed_without_delete(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = None

        processor.process(_submitted_event())

        event = publisher.publish.call_args[0][0]
        assert event.status == DocumentStatus.Failed
        assert event.error_reason == "payload not available"
        redis.delete.assert_not_called()

    def test_crypto_error_publishes_failed_and_deletes(self) -> None:
        processor, redis, publisher, _ = _make_processor()
        redis.fetch.return_value = SubmissionPayload(payload=PLAINTEXT, passphrase=PASSPHRASE)
        # n must be a power of 2; scrypt rejects this, forcing a failure mid-processing.
        processor._scrypt_params = crypto.ScryptParameters(n=3, r=8, p=1)

        processor.process(_submitted_event())

        event = publisher.publish.call_args[0][0]
        assert event.status == DocumentStatus.Failed
        assert event.error_reason == "processing error"
        redis.delete.assert_called_once_with(DOCUMENT_ID)
