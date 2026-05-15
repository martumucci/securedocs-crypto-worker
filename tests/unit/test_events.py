import json
from base64 import b64encode
from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from securedocs_worker.events import (
    DocumentProcessedEvent,
    DocumentStatus,
    DocumentSubmittedEvent,
)


def _b64(value: bytes) -> str:
    return b64encode(value).decode("ascii")


class TestDocumentSubmittedEvent:
    def test_parses_wire_format_with_camel_case_fields(self) -> None:
        wire = {
            "messageId": "11111111-1111-1111-1111-111111111111",
            "documentId": "22222222-2222-2222-2222-222222222222",
            "submittedAt": "2026-05-14T12:34:56.789+00:00",
        }

        event = DocumentSubmittedEvent.model_validate(wire)

        assert event.message_id == UUID("11111111-1111-1111-1111-111111111111")
        assert event.document_id == UUID("22222222-2222-2222-2222-222222222222")
        assert event.submitted_at == datetime(2026, 5, 14, 12, 34, 56, 789000, tzinfo=timezone.utc)

    def test_parses_from_raw_json(self) -> None:
        raw = json.dumps(
            {
                "messageId": "11111111-1111-1111-1111-111111111111",
                "documentId": "22222222-2222-2222-2222-222222222222",
                "submittedAt": "2026-05-14T12:34:56Z",
            }
        )

        event = DocumentSubmittedEvent.model_validate_json(raw)

        assert isinstance(event.message_id, UUID)

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            DocumentSubmittedEvent.model_validate(
                {
                    "messageId": "11111111-1111-1111-1111-111111111111",
                    # documentId missing
                    "submittedAt": "2026-05-14T12:34:56Z",
                }
            )

    def test_invalid_uuid_raises(self) -> None:
        with pytest.raises(ValidationError):
            DocumentSubmittedEvent.model_validate(
                {
                    "messageId": "not-a-uuid",
                    "documentId": "22222222-2222-2222-2222-222222222222",
                    "submittedAt": "2026-05-14T12:34:56Z",
                }
            )


class TestDocumentProcessedEvent:
    def _success_wire(self) -> dict[str, object]:
        return {
            "messageId": "11111111-1111-1111-1111-111111111111",
            "documentId": "22222222-2222-2222-2222-222222222222",
            "status": "Success",
            "ciphertext": _b64(b"\x01\x02\x03"),
            "nonce": _b64(b"\x04" * 12),
            "tag": _b64(b"\x05" * 16),
            "salt": _b64(b"\x06" * 16),
            "kdfAlgorithm": "scrypt",
            "kdfParameters": "{\"n\":16384,\"r\":8,\"p\":1}",
            "hash": _b64(b"\x07" * 32),
            "signature": _b64(b"\x08" * 64),
            "algorithm": "AES-256-GCM",
            "processedAt": "2026-05-14T12:34:56Z",
        }

    def test_parses_success_wire_with_decoded_base64(self) -> None:
        event = DocumentProcessedEvent.model_validate(self._success_wire())

        assert event.status == DocumentStatus.Success
        assert event.ciphertext == b"\x01\x02\x03"
        assert event.nonce == b"\x04" * 12
        assert event.tag == b"\x05" * 16
        assert event.salt == b"\x06" * 16
        assert event.hash == b"\x07" * 32
        assert event.signature == b"\x08" * 64
        assert event.kdf_algorithm == "scrypt"
        assert event.algorithm == "AES-256-GCM"

    def test_parses_failed_wire_with_default_nullables(self) -> None:
        wire = {
            "messageId": "11111111-1111-1111-1111-111111111111",
            "documentId": "22222222-2222-2222-2222-222222222222",
            "status": "Failed",
            "errorReason": "payload not available",
            "processedAt": "2026-05-14T12:34:56Z",
        }

        event = DocumentProcessedEvent.model_validate(wire)

        assert event.status == DocumentStatus.Failed
        assert event.error_reason == "payload not available"
        assert event.ciphertext is None
        assert event.salt is None
        assert event.signature is None

    def test_serializes_back_to_wire_format(self) -> None:
        event = DocumentProcessedEvent(
            message_id=UUID("11111111-1111-1111-1111-111111111111"),
            document_id=UUID("22222222-2222-2222-2222-222222222222"),
            status=DocumentStatus.Success,
            ciphertext=b"\x01\x02\x03",
            nonce=b"\x04" * 12,
            tag=b"\x05" * 16,
            salt=b"\x06" * 16,
            kdf_algorithm="scrypt",
            kdf_parameters="{\"n\":16384,\"r\":8,\"p\":1}",
            hash=b"\x07" * 32,
            signature=b"\x08" * 64,
            algorithm="AES-256-GCM",
            processed_at=datetime(2026, 5, 14, 12, 34, 56, tzinfo=timezone.utc),
        )

        wire = event.model_dump(by_alias=True, mode="json")

        assert wire["messageId"] == "11111111-1111-1111-1111-111111111111"
        assert wire["documentId"] == "22222222-2222-2222-2222-222222222222"
        assert wire["status"] == "Success"
        assert wire["ciphertext"] == _b64(b"\x01\x02\x03")
        assert wire["kdfAlgorithm"] == "scrypt"

    def test_round_trips_through_json(self) -> None:
        original = self._success_wire()

        event = DocumentProcessedEvent.model_validate(original)
        serialized = event.model_dump(by_alias=True, mode="json")

        assert serialized["ciphertext"] == original["ciphertext"]
        assert serialized["salt"] == original["salt"]
        assert serialized["status"] == original["status"]

    def test_unknown_status_raises(self) -> None:
        wire = self._success_wire()
        wire["status"] = "Pending"

        with pytest.raises(ValidationError):
            DocumentProcessedEvent.model_validate(wire)

    def test_invalid_base64_raises(self) -> None:
        wire = self._success_wire()
        wire["ciphertext"] = "not-valid-base64!@#"

        with pytest.raises(ValidationError):
            DocumentProcessedEvent.model_validate(wire)
