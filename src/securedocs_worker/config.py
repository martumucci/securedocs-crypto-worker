from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class RedisSettings(BaseModel):
    url: str
    payload_key_prefix: str = "payload:"


class RabbitMqSettings(BaseModel):
    url: str
    submitted_queue: str = "securedocs.document-submitted"
    submitted_exchange: str = (
        "SecureDocs.Application.Documents.IntegrationEvents:DocumentSubmittedIntegrationEvent"
    )
    processed_exchange: str = (
        "SecureDocs.Application.Documents.IntegrationEvents:DocumentProcessedIntegrationEvent"
    )
    prefetch_count: int = 1


class KeySettings(BaseModel):
    private_key_path: Path = Path("./keys/ed25519.private")
    public_key_path: Path = Path("./keys/ed25519.public")


class CryptoSettings(BaseModel):
    scrypt_n: int = 16384
    scrypt_r: int = 8
    scrypt_p: int = 1


class HealthcheckSettings(BaseModel):
    port: int = 8080


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    redis: RedisSettings
    rabbitmq: RabbitMqSettings
    keys: KeySettings = Field(default_factory=KeySettings)
    crypto: CryptoSettings = Field(default_factory=CryptoSettings)
    healthcheck: HealthcheckSettings = Field(default_factory=HealthcheckSettings)
