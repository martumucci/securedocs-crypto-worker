from pathlib import Path

import pytest
from pydantic import ValidationError

from securedocs_worker.config import Settings


def _set_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS__URL", "redis://r:6379")
    monkeypatch.setenv("RABBITMQ__URL", "amqp://u:p@host:5672/")


def test_loads_required_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)

    settings = Settings(_env_file=None)

    assert settings.redis.url == "redis://r:6379"
    assert settings.rabbitmq.url == "amqp://u:p@host:5672/"


def test_uses_defaults_when_optional_env_vars_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required(monkeypatch)

    settings = Settings(_env_file=None)

    assert settings.redis.payload_key_prefix == "payload:"
    assert settings.rabbitmq.submitted_queue == "securedocs.document-submitted"
    assert settings.rabbitmq.prefetch_count == 1
    assert settings.healthcheck.port == 8080
    assert settings.keys.private_key_path == Path("./keys/ed25519.private")
    assert settings.keys.public_key_path == Path("./keys/ed25519.public")


def test_overrides_optional_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    monkeypatch.setenv("HEALTHCHECK__PORT", "9090")
    monkeypatch.setenv("KEYS__PRIVATE_KEY_PATH", "/tmp/p.private")
    monkeypatch.setenv("RABBITMQ__PREFETCH_COUNT", "5")

    settings = Settings(_env_file=None)

    assert settings.healthcheck.port == 9090
    assert settings.keys.private_key_path == Path("/tmp/p.private")
    assert settings.rabbitmq.prefetch_count == 5


def test_missing_redis_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS__URL", raising=False)
    monkeypatch.setenv("RABBITMQ__URL", "amqp://u:p@host:5672/")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_missing_rabbitmq_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS__URL", "redis://r:6379")
    monkeypatch.delenv("RABBITMQ__URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_invalid_port_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    monkeypatch.setenv("HEALTHCHECK__PORT", "not-a-number")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
