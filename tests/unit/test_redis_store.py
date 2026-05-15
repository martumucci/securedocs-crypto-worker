from unittest.mock import Mock
from uuid import UUID

import pytest
from pydantic import ValidationError
from redis import Redis

from securedocs_worker.redis_store import RedisPayloadStore, SubmissionPayload

DOCUMENT_ID = UUID("11111111-1111-1111-1111-111111111111")


def _make_store(prefix: str = "payload:") -> tuple[RedisPayloadStore, Mock]:
    client = Mock(spec=Redis)
    store = RedisPayloadStore(client=client, key_prefix=prefix)
    return store, client


def test_fetch_returns_parsed_submission_when_key_exists() -> None:
    store, client = _make_store()
    client.get.return_value = b'{"payload":"hello","passphrase":"correct horse battery staple"}'

    result = store.fetch(DOCUMENT_ID)

    assert result == SubmissionPayload(
        payload="hello",
        passphrase="correct horse battery staple",
    )


def test_fetch_returns_none_when_key_missing() -> None:
    store, client = _make_store()
    client.get.return_value = None

    result = store.fetch(DOCUMENT_ID)

    assert result is None


def test_fetch_uses_configured_prefix() -> None:
    store, client = _make_store(prefix="custom-prefix:")
    client.get.return_value = b'{"payload":"x","passphrase":"yyyyyyyyyyyyy"}'

    store.fetch(DOCUMENT_ID)

    client.get.assert_called_once_with(f"custom-prefix:{DOCUMENT_ID}")


def test_fetch_accepts_str_input_when_decode_responses_enabled() -> None:
    store, client = _make_store()
    client.get.return_value = '{"payload":"hello","passphrase":"correct horse battery staple"}'

    result = store.fetch(DOCUMENT_ID)

    assert result is not None
    assert result.payload == "hello"


def test_fetch_raises_on_malformed_json() -> None:
    store, client = _make_store()
    client.get.return_value = b"not-json"

    with pytest.raises(ValidationError):
        store.fetch(DOCUMENT_ID)


def test_fetch_raises_when_required_field_missing() -> None:
    store, client = _make_store()
    client.get.return_value = b'{"payload":"hello"}'

    with pytest.raises(ValidationError):
        store.fetch(DOCUMENT_ID)


def test_delete_calls_client_with_correct_key() -> None:
    store, client = _make_store()

    store.delete(DOCUMENT_ID)

    client.delete.assert_called_once_with(f"payload:{DOCUMENT_ID}")
