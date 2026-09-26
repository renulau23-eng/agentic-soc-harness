"""Typed configuration. Everything comes from environment variables (prefix
``ASH_``) or a ``.env`` file; model profiles, users and policy can also be
loaded from YAML for on-prem operators who prefer files to env.

Model profiles are discovered dynamically: any ``ASH_MODEL_<PROFILE>_PROVIDER``
variable defines a profile named ``<profile>`` (lower-cased).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from ash.core.errors import ConfigurationError


class ModelProfile(BaseModel):
    """One named way to reach a model, e.g. ``reasoning`` → Nemotron on NIM."""

    name: str
    provider: str  # mock | openai_compatible | nemotron | sovereign
    model: str = "mock"
    base_url: str | None = None
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout_s: float = 120.0
    reasoning: bool = True  # Nemotron thinking mode toggle
    extra: dict[str, Any] = Field(default_factory=dict)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ASH_", env_file=".env", extra="ignore")

    # --- service
    app_name: str = "agentic-soc-harness"
    environment: str = "development"  # development | staging | production
    log_level: str = "INFO"
    log_json: bool = True

    # --- persistence
    database_url: str = "sqlite:///./ash.db"

    # --- auth
    jwt_secret: str = "change-me-in-production"
    jwt_issuer: str = "ash"
    jwt_ttl_seconds: int = 3600
    api_keys: str = ""  # "key:name:role1|role2,key2:name2:role"
    users_file: str | None = None  # YAML: [{username, password_hash, roles}]
    bootstrap_admin_password: str | None = None  # dev convenience only

    # --- governance
    policy_file: str | None = None
    approval_ttl_seconds: int = 4 * 3600
    rate_limit_per_minute: int = 120
    guardrail_webhook_url: str | None = None  # AgentPEP / LLM Firewall / Thoth

    # --- runtime
    max_agent_steps: int = 12
    default_model_profile: str = "reasoning"
    models_file: str | None = None  # YAML list of profiles

    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    # ------------------------------------------------------------------ #
    def model_profiles(self) -> dict[str, ModelProfile]:
        """Merge YAML-defined and env-defined model profiles (env wins)."""
        profiles: dict[str, ModelProfile] = {}
        if self.models_file:
            data = _load_yaml(self.models_file)
            for item in data.get("models", []):
                p = ModelProfile(**item)
                profiles[p.name] = p

        prefix = "ASH_MODEL_"
        names = {
            k[len(prefix) : -len("_PROVIDER")].lower()
            for k in os.environ
            if k.startswith(prefix) and k.endswith("_PROVIDER")
        }
        for name in names:

            def env(key: str, default: str | None = None, _n: str = name) -> str | None:
                return os.environ.get(f"{prefix}{_n.upper()}_{key}", default)

            profiles[name] = ModelProfile(
                name=name,
                provider=env("PROVIDER"),
                model=env("MODEL", "mock"),
                base_url=env("BASE_URL"),
                api_key=env("API_KEY"),
                temperature=float(env("TEMPERATURE", "0.1")),
                max_tokens=int(env("MAX_TOKENS", "2048")),
                timeout_s=float(env("TIMEOUT_S", "120")),
                reasoning=env("REASONING", "true").lower() in {"1", "true", "yes"},
            )

        if not profiles:
            profiles["reasoning"] = ModelProfile(name="reasoning", provider="mock", model="mock")
        return profiles

    def validate_for_environment(self) -> None:
        if self.is_production() and self.jwt_secret == "change-me-in-production":
            raise ConfigurationError("ASH_JWT_SECRET must be set in production")
        if self.is_production() and self.bootstrap_admin_password:
            raise ConfigurationError("ASH_BOOTSTRAP_ADMIN_PASSWORD is not allowed in production")


def _load_yaml(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise ConfigurationError(f"config file not found: {path}")
    with p.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
