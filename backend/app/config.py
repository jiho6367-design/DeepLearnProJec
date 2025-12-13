import os
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"),
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field("development")
    database_url: str = Field("sqlite:///./phishguard.db")
    google_client_id: Optional[str] = Field(None)
    google_client_secret: Optional[str] = Field(None)
    google_redirect_uri: str = Field("http://localhost:8000/api/auth/google/callback")
    frontend_base_url: str = Field("http://localhost:3000")
    allowed_origins: str = Field("")
    encryption_key: Optional[str] = Field(None)
    session_ttl_minutes: int = Field(60 * 24 * 7)
    oauth_state_ttl_minutes: int = Field(10)
    cookie_domain: Optional[str] = Field(None)
    cookie_secure: Optional[bool] = Field(None)
    cookie_samesite: Optional[str] = Field(None)

    @field_validator("allowed_origins", mode="before")
    def normalize_origins(cls, v: str) -> str:
        return v or ""

    @property
    def allowed_origins_list(self) -> List[str]:
        if not self.allowed_origins:
            return [self.frontend_base_url]
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def effective_cookie_secure(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.environment.lower() == "production"

    @property
    def effective_cookie_samesite(self) -> str:
        if self.cookie_samesite:
            return self.cookie_samesite
        return "none" if self.cookie_domain else "lax"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
