from base64 import b64decode, b64encode
from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer
from pydantic.alias_generators import to_camel


def _decode_base64(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return b64decode(value, validate=True)
    raise TypeError(f"Expected bytes or str, got {type(value).__name__}")


def _encode_base64(value: bytes) -> str:
    return b64encode(value).decode("ascii")


WireBytes = Annotated[
    bytes,
    BeforeValidator(_decode_base64),
    PlainSerializer(_encode_base64, when_used="json"),
]


class _CamelCaseModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )


class DocumentStatus(str, Enum):
    Success = "Success"
    Failed = "Failed"


class DocumentSubmittedEvent(_CamelCaseModel):
    message_id: UUID
    document_id: UUID
    submitted_at: datetime


class DocumentProcessedEvent(_CamelCaseModel):
    message_id: UUID
    document_id: UUID
    status: DocumentStatus
    ciphertext: WireBytes | None = None
    nonce: WireBytes | None = None
    tag: WireBytes | None = None
    salt: WireBytes | None = None
    kdf_algorithm: str | None = None
    kdf_parameters: str | None = None
    hash: WireBytes | None = None
    signature: WireBytes | None = None
    algorithm: str | None = None
    error_reason: str | None = None
    processed_at: datetime
