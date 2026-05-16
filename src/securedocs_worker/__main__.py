import signal
from types import FrameType

import structlog
from redis import Redis

from securedocs_worker import crypto
from securedocs_worker.config import Settings
from securedocs_worker.health import start_health_server
from securedocs_worker.keystore import load_or_generate_signing_key
from securedocs_worker.logging_setup import configure_logging
from securedocs_worker.processor import DocumentProcessor
from securedocs_worker.rabbitmq import MassTransitConsumer, MassTransitPublisher
from securedocs_worker.redis_store import RedisPayloadStore

logger = structlog.get_logger().bind(logger=__name__)


def main() -> None:
    configure_logging()

    settings = Settings()

    signing_key = load_or_generate_signing_key(
        settings.keys.private_key_path,
        settings.keys.public_key_path,
    )

    redis_client = Redis.from_url(settings.redis.url)
    redis_store = RedisPayloadStore(redis_client, settings.redis.payload_key_prefix)

    publisher = MassTransitPublisher(
        settings.rabbitmq.url,
        settings.rabbitmq.processed_exchange,
    )
    publisher.connect()

    processor = DocumentProcessor(
        redis_store=redis_store,
        publisher=publisher,
        signing_key=signing_key,
        scrypt_params=crypto.ScryptParameters(
            n=settings.crypto.scrypt_n,
            r=settings.crypto.scrypt_r,
            p=settings.crypto.scrypt_p,
        ),
    )

    consumer = MassTransitConsumer(
        url=settings.rabbitmq.url,
        queue=settings.rabbitmq.submitted_queue,
        exchange=settings.rabbitmq.submitted_exchange,
        prefetch_count=settings.rabbitmq.prefetch_count,
    )

    def shutdown(signum: int, _frame: FrameType | None) -> None:
        logger.info("shutdown signal received; stopping consumer", signum=signum)
        consumer.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    start_health_server(settings.healthcheck.port)

    try:
        consumer.consume(processor.process)
    finally:
        publisher.close()
        redis_client.close()
        logger.info("worker stopped")


if __name__ == "__main__":
    main()
