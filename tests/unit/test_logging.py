import json
from collections.abc import Iterator

import pytest
import structlog

from securedocs_worker.logging_setup import configure_logging


@pytest.fixture(autouse=True)
def _clean_contextvars() -> Iterator[None]:
    structlog.contextvars.clear_contextvars()
    yield
    structlog.contextvars.clear_contextvars()


def test_emits_json_with_standard_fields(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging()

    structlog.get_logger().bind(logger="test.module").info("hello", foo="bar")

    record = json.loads(capsys.readouterr().out)
    assert record["event"] == "hello"
    assert record["foo"] == "bar"
    assert record["level"] == "info"
    assert record["logger"] == "test.module"
    assert "timestamp" in record


def test_correlation_id_from_contextvars_appears_in_logs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging()

    structlog.contextvars.bind_contextvars(correlation_id="abc-123")
    structlog.get_logger().info("with correlation")

    record = json.loads(capsys.readouterr().out)
    assert record["correlation_id"] == "abc-123"


def test_cleared_contextvars_not_in_subsequent_logs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging()

    structlog.contextvars.bind_contextvars(correlation_id="abc-123")
    structlog.contextvars.clear_contextvars()
    structlog.get_logger().info("no correlation")

    record = json.loads(capsys.readouterr().out)
    assert "correlation_id" not in record


def test_exception_is_rendered(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging()

    try:
        raise ValueError("boom")
    except ValueError:
        structlog.get_logger().exception("caught it")

    record = json.loads(capsys.readouterr().out)
    assert record["event"] == "caught it"
    assert "boom" in record["exception"]
