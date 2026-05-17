from typing import cast
from uuid import UUID

from pydantic import BaseModel
from redis import Redis


class SubmissionPayload(BaseModel):
    payload: str
    passphrase: str


class RedisPayloadStore:
    def __init__(self, client: Redis, key_prefix: str = "payload:") -> None:
        self._client = client
        self._key_prefix = key_prefix

    def fetch(self, document_id: UUID) -> SubmissionPayload | None:
        key = self._key_for(document_id)
        # redis-py types .get() as Awaitable | Any (it unions the sync/async
        # client); this is the sync client, so the result is str | bytes | None.
        raw = cast(str | bytes | None, self._client.get(key))
        if raw is None:
            return None
        return SubmissionPayload.model_validate_json(raw)

    def delete(self, document_id: UUID) -> None:
        key = self._key_for(document_id)
        self._client.delete(key)

    def _key_for(self, document_id: UUID) -> str:
        return f"{self._key_prefix}{document_id}"
