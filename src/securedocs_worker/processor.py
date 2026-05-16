import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from securedocs_worker import crypto
from securedocs_worker.events import (
    DocumentProcessedEvent,
    DocumentStatus,
    DocumentSubmittedEvent,
)
from securedocs_worker.rabbitmq import MassTransitPublisher
from securedocs_worker.redis_store import RedisPayloadStore, SubmissionPayload

logger = structlog.get_logger().bind(logger=__name__)

ALGORITHM = "AES-256-GCM"
KDF_ALGORITHM = "scrypt"


def canonical_timestamp(dt: datetime) -> str:
    """Canonical UTC ISO 8601 with millisecond precision and 'Z' suffix.

    This format is part of the signing protocol: the verifier must reconstruct
    the exact same string to validate the Ed25519 signature.
    """
    utc = dt.astimezone(timezone.utc)
    millis = utc.microsecond // 1000
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"


class DocumentProcessor:
    def __init__(
        self,
        redis_store: RedisPayloadStore,
        publisher: MassTransitPublisher,
        signing_key: Ed25519PrivateKey,
        scrypt_params: crypto.ScryptParameters,
    ) -> None:
        self._redis = redis_store
        self._publisher = publisher
        self._signing_key = signing_key
        self._scrypt_params = scrypt_params

    def process(
        self,
        event: DocumentSubmittedEvent,
        correlation_id: str | None = None,
    ) -> None:
        document_id = event.document_id

        submission = self._redis.fetch(document_id)
        if submission is None:
            logger.warning("payload not available", document_id=str(document_id))
            self._publish_failed(document_id, "payload not available", correlation_id)
            return

        try:
            processed = self._encrypt_and_sign(document_id, submission)
        except Exception:
            logger.exception("processing error", document_id=str(document_id))
            self._publish_failed(document_id, "processing error", correlation_id)
            self._redis.delete(document_id)
            return

        self._publisher.publish(processed, correlation_id)
        self._redis.delete(document_id)
        logger.info("document processed", document_id=str(document_id))

    def _encrypt_and_sign(
        self,
        document_id: UUID,
        submission: SubmissionPayload,
    ) -> DocumentProcessedEvent:
        plaintext = submission.payload.encode("utf-8")

        salt = crypto.generate_salt()
        nonce = crypto.generate_nonce()
        key = crypto.derive_key(submission.passphrase, salt, self._scrypt_params)
        blob = crypto.encrypt_aes_gcm(key, plaintext, nonce)
        digest = crypto.compute_hash(plaintext)

        now = datetime.now(timezone.utc)
        processed_at = now.replace(microsecond=(now.microsecond // 1000) * 1000)
        signed_message = digest + canonical_timestamp(processed_at).encode("utf-8")
        signature = crypto.sign_ed25519(self._signing_key, signed_message)

        kdf_parameters = json.dumps(
            {
                "n": self._scrypt_params.n,
                "r": self._scrypt_params.r,
                "p": self._scrypt_params.p,
            },
            separators=(",", ":"),
        )

        return DocumentProcessedEvent(
            message_id=uuid4(),
            document_id=document_id,
            status=DocumentStatus.Success,
            ciphertext=blob.ciphertext,
            nonce=blob.nonce,
            tag=blob.tag,
            salt=salt,
            kdf_algorithm=KDF_ALGORITHM,
            kdf_parameters=kdf_parameters,
            hash=digest,
            signature=signature,
            algorithm=ALGORITHM,
            processed_at=processed_at,
        )

    def _publish_failed(
        self,
        document_id: UUID,
        reason: str,
        correlation_id: str | None,
    ) -> None:
        event = DocumentProcessedEvent(
            message_id=uuid4(),
            document_id=document_id,
            status=DocumentStatus.Failed,
            error_reason=reason,
            processed_at=datetime.now(timezone.utc),
        )
        self._publisher.publish(event, correlation_id)
