import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from securedocs_worker.rabbitmq import parse_envelope

VALID_INNER_MESSAGE = {
    "messageId": "11111111-1111-1111-1111-111111111111",
    "documentId": "22222222-2222-2222-2222-222222222222",
    "submittedAt": "2026-05-14T12:34:56.789+00:00",
}


def _envelope(headers: dict[str, str] | None = None) -> bytes:
    envelope = {
        "messageId": "33333333-3333-3333-3333-333333333333",
        "conversationId": "44444444-4444-4444-4444-444444444444",
        "sourceAddress": "rabbitmq://api/source",
        "destinationAddress": "rabbitmq://api/destination",
        "messageType": [
            "urn:message:SecureDocs.Application.Documents.IntegrationEvents:DocumentSubmittedIntegrationEvent"
        ],
        "message": VALID_INNER_MESSAGE,
        "sentTime": "2026-05-14T12:34:56Z",
        "host": {"machineName": "test"},
    }
    if headers is not None:
        envelope["headers"] = headers
    return json.dumps(envelope).encode("utf-8")


def test_parse_envelope_extracts_inner_message() -> None:
    event, _ = parse_envelope(_envelope())

    assert event.message_id == UUID("11111111-1111-1111-1111-111111111111")
    assert event.document_id == UUID("22222222-2222-2222-2222-222222222222")


def test_parse_envelope_extracts_correlation_id_from_headers() -> None:
    _, correlation_id = parse_envelope(_envelope(headers={"X-Correlation-Id": "trace-001"}))

    assert correlation_id == "trace-001"


def test_parse_envelope_returns_none_when_correlation_id_absent() -> None:
    _, correlation_id = parse_envelope(_envelope(headers={"Other-Header": "value"}))

    assert correlation_id is None


def test_parse_envelope_returns_none_when_headers_absent() -> None:
    _, correlation_id = parse_envelope(_envelope())

    assert correlation_id is None


def test_parse_envelope_returns_none_when_headers_null() -> None:
    raw = json.dumps(
        {
            "message": VALID_INNER_MESSAGE,
            "headers": None,
        }
    ).encode("utf-8")

    _, correlation_id = parse_envelope(raw)

    assert correlation_id is None


def test_parse_envelope_raises_when_message_key_missing() -> None:
    raw = json.dumps({"messageId": "x", "headers": {}}).encode("utf-8")

    with pytest.raises(KeyError):
        parse_envelope(raw)


def test_parse_envelope_raises_when_inner_message_invalid() -> None:
    invalid_inner = {**VALID_INNER_MESSAGE}
    del invalid_inner["documentId"]
    raw = json.dumps({"message": invalid_inner}).encode("utf-8")

    with pytest.raises(ValidationError):
        parse_envelope(raw)


def test_parse_envelope_raises_when_body_not_json() -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_envelope(b"not json")
