"""Central configuration. Values come from environment variables / .env (pydantic-settings).

Guardrail §9.1: the Elasticsearch credentials configured here MUST be a read-only API key for
anything the agent touches. The lab loader uses a separate *writer* key (``AEGIS_ES_WRITER_*``)
which is never handed to a tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


class ElasticSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_ES_", env_file=".env", extra="ignore")

    url: str = "http://localhost:9200"
    kibana_url: str = "http://localhost:5601"
    # Read-only key used by every agent tool (§9.1).
    readonly_api_key: SecretStr | None = None
    # Writer key used ONLY by lab loaders / snapshot restore. Never exposed to the graph.
    writer_api_key: SecretStr | None = None
    username: str | None = "elastic"
    password: SecretStr | None = None
    verify_certs: bool = False
    index_prefix: str = "aegis"
    request_timeout_s: int = 60


class PostgresSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_PG_", env_file=".env", extra="ignore")

    dsn: str = "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"


class RedisSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_REDIS_", env_file=".env", extra="ignore")

    url: str = "redis://localhost:6379/0"


class DataSettings(BaseSettings):
    """Filesystem layout for raw downloads, Parquet snapshots and ground truth."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_DATA_", env_file=".env", extra="ignore")

    root: Path = REPO_ROOT / "data"

    @property
    def raw(self) -> Path:
        return self.root / "raw"

    @property
    def parquet(self) -> Path:
        return self.root / "parquet"

    @property
    def snapshots(self) -> Path:
        return self.root / "snapshots"

    @property
    def ground_truth(self) -> Path:
        return self.root / "ground_truth"

    @property
    def rules(self) -> Path:
        return self.root / "rules"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    env: Literal["dev", "ci", "prod"] = "dev"
    # --offline: everything runs from Parquet via DuckDB, zero external calls (§8.5).
    offline: bool = False
    log_level: str = "INFO"
    seed: int = 1337

    elastic: ElasticSettings = Field(default_factory=ElasticSettings)
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    data: DataSettings = Field(default_factory=DataSettings)


def get_settings() -> Settings:
    return Settings()
