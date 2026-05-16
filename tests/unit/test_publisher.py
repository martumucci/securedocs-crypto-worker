from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import UUID

import pika
import pytest

from securedocs_worker.events import DocumentProcessedEvent, DocumentStatus
from securedocs_worker.rabbitmq import MassTransitPublisher, build_envelope

EXCHANGE = "SecureDocs.Application.Documents.IntegrationEvents:DocumentProcessedIntegrationEvent"


def _success_event() -> DocumentProcessedEvent:
    return DocumentProcessedEvent(
        message_id=UUID("11111111-1111-1111-1111-111111111111"),
        document_id=UUID("22222222-2222-2222-2222-222222222222"),
        status=DocumentStatus.Success,
        ciphertext=b"\x01\x02\x03",
        nonce=b"\x04" * 12,
        tag=b"\x05" * 16,
        salt=b"\x06" * 16,
        kdf_algorithm="scrypt",
        kdf_parameters='{"n":16384,"r":8,"p":1}',
        hash=b"\x07" * 32,
        signature=b"\x08" * 64,
        algorithm="AES-256-GCM",
        processed_at=datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_envelope_message_type_is_masstransit_urn() -> None:
    envelope = build_envelope(_success_event(), EXCHANGE, correlation_id=None)

    assert envelope["messageType"] == [f"urn:message:{EXCHANGE}"]


def test_envelope_wraps_event_as_camel_case_message() -> None:
    envelope = build_envelope(_success_event(), EXCHANGE, correlation_id=None)

    message = envelope["message"]
    assert message["documentId"] == "22222222-2222-2222-2222-222222222222"
    assert message["status"] == "Success"
    assert message["kdfAlgorithm"] == "scrypt"


def test_envelope_message_encodes_bytes_as_base64() -> None:
    envelope = build_envelope(_success_event(), EXCHANGE, correlation_id=None)

    message = envelope["message"]
    # base64 of b"\x01\x02\x03" is "AQID"
    assert message["ciphertext"] == "AQID"


def test_envelope_includes_correlation_id_when_provided() -> None:
    envelope = build_envelope(_success_event(), EXCHANGE, correlation_id="trace-001")

    assert envelope["headers"] == {"X-Correlation-Id": "trace-001"}


def test_envelope_headers_empty_when_no_correlation_id() -> None:
    envelope = build_envelope(_success_event(), EXCHANGE, correlation_id=None)

    assert envelope["headers"] == {}


def test_envelope_has_message_id_and_sent_time() -> None:
    envelope = build_envelope(_success_event(), EXCHANGE, correlation_id=None)

    assert "messageId" in envelope
    assert "sentTime" in envelope
    # sentTime parses as ISO 8601
    datetime.fromisoformat(str(envelope["sentTime"]))


def test_envelope_round_trips_failed_event() -> None:
    failed = DocumentProcessedEvent(
        message_id=UUID("11111111-1111-1111-1111-111111111111"),
        document_id=UUID("22222222-2222-2222-2222-222222222222"),
        status=DocumentStatus.Failed,
        error_reason="payload not available",
        processed_at=datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
    )

    envelope = build_envelope(failed, EXCHANGE, correlation_id=None)

    message = envelope["message"]
    assert message["status"] == "Failed"
    assert message["errorReason"] == "payload not available"
    assert message["ciphertext"] is None


def test_publish_reconnects_and_retries_once_after_connection_loss() -> None:
    publisher = MassTransitPublisher("amqp://unused", EXCHANGE)

    dead_channel = MagicMock()
    dead_channel.basic_publish.side_effect = pika.exceptions.ChannelWrongStateError(
        "Channel is closed."
    )
    fresh_channel = MagicMock()

    publisher._channel = dead_channel

    def fake_connect() -> None:
        publisher._channel = fresh_channel
        publisher._connection = MagicMock(is_open=True)

    publisher.connect = fake_connect  # type: ignore[method-assign]

    publisher.publish(_success_event())

    dead_channel.basic_publish.assert_called_once()
    fresh_channel.basic_publish.assert_called_once()


def test_publish_propagates_error_if_reconnect_also_fails() -> None:
    publisher = MassTransitPublisher("amqp://unused", EXCHANGE)

    broken_channel = MagicMock()
    broken_channel.basic_publish.side_effect = pika.exceptions.ChannelWrongStateError(
        "Channel is closed."
    )
    publisher._channel = broken_channel

    def fake_connect() -> None:
        publisher._channel = broken_channel
        publisher._connection = MagicMock(is_open=True)

    publisher.connect = fake_connect  # type: ignore[method-assign]

    with pytest.raises(pika.exceptions.AMQPError):
        publisher.publish(_success_event())
