import base64
import json
import threading
import time
from collections.abc import Iterator
from uuid import UUID, uuid4

import pika
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from redis import Redis
from testcontainers.rabbitmq import RabbitMqContainer
from testcontainers.redis import RedisContainer

from securedocs_worker import crypto
from securedocs_worker.events import DocumentProcessedEvent, DocumentStatus
from securedocs_worker.processor import DocumentProcessor, canonical_timestamp
from securedocs_worker.rabbitmq import MassTransitConsumer, MassTransitPublisher
from securedocs_worker.redis_store import RedisPayloadStore

pytestmark = pytest.mark.integration

SUBMITTED_EXCHANGE = (
    "SecureDocs.Application.Documents.IntegrationEvents:DocumentSubmittedIntegrationEvent"
)
SUBMITTED_QUEUE = "securedocs.document-submitted"
PROCESSED_EXCHANGE = (
    "SecureDocs.Application.Documents.IntegrationEvents:DocumentProcessedIntegrationEvent"
)
CAPTURE_QUEUE = "test.capture.processed"

PLAINTEXT = b"end to end legal document"
PASSPHRASE = "correct horse battery staple"
TEST_SCRYPT = crypto.ScryptParameters(n=1024, r=8, p=1)


@pytest.fixture(scope="module")
def redis_container() -> Iterator[RedisContainer]:
    with RedisContainer("redis:7-alpine") as container:
        yield container


@pytest.fixture(scope="module")
def rabbitmq_container() -> Iterator[RabbitMqContainer]:
    with RabbitMqContainer(
        "rabbitmq:3.13-management-alpine",
        username="securedocs",
        password="securedocs",
    ) as container:
        yield container


def _rabbit_url(container: RabbitMqContainer) -> str:
    params = container.get_connection_params()
    creds = params.credentials
    return f"amqp://{creds.username}:{creds.password}@{params.host}:{params.port}/"


def _submitted_envelope(document_id: UUID) -> bytes:
    return json.dumps(
        {
            "messageId": str(uuid4()),
            "messageType": [f"urn:message:{SUBMITTED_EXCHANGE}"],
            "message": {
                "messageId": str(uuid4()),
                "documentId": str(document_id),
                "submittedAt": "2026-05-16T12:00:00Z",
            },
            "headers": {"X-Correlation-Id": "it-trace-1"},
        }
    ).encode("utf-8")


def test_submitted_document_is_encrypted_signed_and_published(
    redis_container: RedisContainer,
    rabbitmq_container: RabbitMqContainer,
) -> None:
    rabbit_url = _rabbit_url(rabbitmq_container)
    redis_client: Redis = redis_container.get_client()
    document_id = uuid4()

    # Declare topology + capture queue from a dedicated test connection.
    test_conn = pika.BlockingConnection(pika.URLParameters(rabbit_url))
    test_ch = test_conn.channel()
    test_ch.exchange_declare(SUBMITTED_EXCHANGE, exchange_type="fanout", durable=True)
    test_ch.queue_declare(SUBMITTED_QUEUE, durable=True)
    test_ch.queue_bind(SUBMITTED_QUEUE, SUBMITTED_EXCHANGE)
    test_ch.exchange_declare(PROCESSED_EXCHANGE, exchange_type="fanout", durable=True)
    test_ch.queue_declare(CAPTURE_QUEUE, durable=True)
    test_ch.queue_bind(CAPTURE_QUEUE, PROCESSED_EXCHANGE)

    # Seed Redis exactly as the API would.
    redis_client.set(
        f"payload:{document_id}",
        json.dumps(
            {
                "payload": base64.b64encode(PLAINTEXT).decode("ascii"),
                "passphrase": PASSPHRASE,
            }
        ),
    )

    # Publish the trigger; the durable bound queue retains it until the consumer connects.
    test_ch.basic_publish(
        exchange=SUBMITTED_EXCHANGE,
        routing_key="",
        body=_submitted_envelope(document_id),
    )

    # Build the real worker pipeline against the containers.
    signing_key = Ed25519PrivateKey.generate()
    publisher = MassTransitPublisher(rabbit_url, PROCESSED_EXCHANGE)
    publisher.connect()
    processor = DocumentProcessor(
        redis_store=RedisPayloadStore(redis_client),
        publisher=publisher,
        signing_key=signing_key,
        scrypt_params=TEST_SCRYPT,
    )
    consumer = MassTransitConsumer(
        url=rabbit_url,
        queue=SUBMITTED_QUEUE,
        exchange=SUBMITTED_EXCHANGE,
        prefetch_count=1,
    )

    worker_thread = threading.Thread(
        target=consumer.consume, args=(processor.process,), daemon=True
    )
    worker_thread.start()

    captured: bytes | None = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        _, _, body = test_ch.basic_get(CAPTURE_QUEUE, auto_ack=True)
        if body is not None:
            captured = body
            break
        time.sleep(0.3)

    consumer.stop()
    worker_thread.join(timeout=5)
    publisher.close()
    test_conn.close()

    assert captured is not None, "worker did not publish a DocumentProcessed message"

    envelope = json.loads(captured)
    assert envelope["messageType"] == [f"urn:message:{PROCESSED_EXCHANGE}"]

    event = DocumentProcessedEvent.model_validate(envelope["message"])
    assert event.status == DocumentStatus.Success
    assert event.document_id == document_id

    # Hash is SHA-256 of the original plaintext.
    assert event.hash == crypto.compute_hash(PLAINTEXT)

    # Signature verifies against the worker's public key.
    signed = event.hash + canonical_timestamp(event.processed_at).encode("utf-8")
    signing_key.public_key().verify(event.signature, signed)

    # Ciphertext decrypts with the key re-derived from passphrase + stored salt.
    key = crypto.derive_key(PASSPHRASE, event.salt, TEST_SCRYPT)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(event.nonce, event.tag)).decryptor()
    recovered = decryptor.update(event.ciphertext) + decryptor.finalize()
    assert recovered == PLAINTEXT

    # Worker deleted the Redis key after processing.
    assert redis_client.get(f"payload:{document_id}") is None
