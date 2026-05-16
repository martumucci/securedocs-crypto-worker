import json
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

import pika
import structlog
from pika.adapters.blocking_connection import BlockingChannel

from securedocs_worker.events import DocumentProcessedEvent, DocumentSubmittedEvent

logger = structlog.get_logger().bind(logger=__name__)

MASSTRANSIT_CONTENT_TYPE = "application/vnd.masstransit+json"

OnSubmittedEvent = Callable[[DocumentSubmittedEvent, str | None], None]


class MassTransitConsumer:
    def __init__(
        self,
        url: str,
        queue: str,
        exchange: str,
        prefetch_count: int = 1,
    ) -> None:
        self._url = url
        self._queue = queue
        self._exchange = exchange
        self._prefetch_count = prefetch_count
        self._connection: pika.BlockingConnection | None = None
        self._channel: BlockingChannel | None = None

    def consume(self, on_message: OnSubmittedEvent) -> None:
        self._connection = pika.BlockingConnection(pika.URLParameters(self._url))
        self._channel = self._connection.channel()
        self._channel.basic_qos(prefetch_count=self._prefetch_count)

        self._channel.exchange_declare(
            exchange=self._exchange,
            exchange_type="fanout",
            durable=True,
        )
        self._channel.queue_declare(queue=self._queue, durable=True)
        self._channel.queue_bind(queue=self._queue, exchange=self._exchange)

        self._channel.basic_consume(
            queue=self._queue,
            on_message_callback=self._make_callback(on_message),
        )

        logger.info("worker consuming", queue=self._queue, exchange=self._exchange)
        self._channel.start_consuming()

    def stop(self) -> None:
        connection = self._connection
        if connection is not None and connection.is_open:
            connection.add_callback_threadsafe(self._shutdown)

    def _shutdown(self) -> None:
        if self._channel is not None and self._channel.is_open:
            self._channel.stop_consuming()
        if self._connection is not None and self._connection.is_open:
            self._connection.close()

    def _make_callback(
        self, on_message: OnSubmittedEvent
    ) -> Callable[[BlockingChannel, pika.spec.Basic.Deliver, pika.BasicProperties, bytes], None]:
        def callback(
            ch: BlockingChannel,
            method: pika.spec.Basic.Deliver,
            properties: pika.BasicProperties,
            body: bytes,
        ) -> None:
            try:
                event, correlation_id = parse_envelope(body)
                structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
                on_message(event, correlation_id)
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except Exception:
                logger.exception("failed to process message; nacking without requeue")
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            finally:
                structlog.contextvars.clear_contextvars()

        return callback


def parse_envelope(body: bytes) -> tuple[DocumentSubmittedEvent, str | None]:
    envelope = json.loads(body)
    message = envelope["message"]
    event = DocumentSubmittedEvent.model_validate(message)
    headers = envelope.get("headers") or {}
    correlation_id = headers.get("X-Correlation-Id")
    return event, correlation_id


def build_envelope(
    event: DocumentProcessedEvent,
    exchange: str,
    correlation_id: str | None,
) -> dict[str, object]:
    return {
        "messageId": str(uuid4()),
        "conversationId": str(uuid4()),
        "messageType": [f"urn:message:{exchange}"],
        "message": event.model_dump(by_alias=True, mode="json"),
        "sentTime": datetime.now(timezone.utc).isoformat(),
        "headers": {"X-Correlation-Id": correlation_id} if correlation_id else {},
    }


class MassTransitPublisher:
    def __init__(self, url: str, exchange: str) -> None:
        self._url = url
        self._exchange = exchange
        self._connection: pika.BlockingConnection | None = None
        self._channel: BlockingChannel | None = None

    def connect(self) -> None:
        self._connection = pika.BlockingConnection(pika.URLParameters(self._url))
        self._channel = self._connection.channel()
        self._channel.exchange_declare(
            exchange=self._exchange,
            exchange_type="fanout",
            durable=True,
        )

    def publish(self, event: DocumentProcessedEvent, correlation_id: str | None = None) -> None:
        if self._channel is None:
            raise RuntimeError("Publisher not connected. Call connect() first.")

        envelope = build_envelope(event, self._exchange, correlation_id)
        body = json.dumps(envelope).encode("utf-8")

        properties = pika.BasicProperties(
            content_type=MASSTRANSIT_CONTENT_TYPE,
            message_id=str(envelope["messageId"]),
            headers={"X-Correlation-Id": correlation_id} if correlation_id else None,
        )

        self._channel.basic_publish(
            exchange=self._exchange,
            routing_key="",
            body=body,
            properties=properties,
        )

    def close(self) -> None:
        if self._connection is not None and self._connection.is_open:
            self._connection.close()
