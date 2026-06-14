from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite:///./securerag.db"

    # App
    app_env: str = "development"
    app_version: str = "1.0.0"
    log_level: str = "INFO"

    # Auth
    api_keys: str = "sk-dev-key-1234"          # raw comma-separated string from env
    api_key_header: str = "X-API-Key"

    # Rate limiting
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60

    # Security
    block_threshold: int = 40
    cors_origins: str = "*"

    # ── derived helpers ──────────────────────────────────────────────────────

    def get_api_keys(self) -> List[str]:
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    def get_cors_origins(self) -> List[str]:
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
