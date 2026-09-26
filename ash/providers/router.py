"""Model router: resolves a named profile ("reasoning", "fast", "sovereign")
to a provider instance. Agents ask for a profile name, never a vendor."""

from __future__ import annotations

from collections.abc import Callable

from ash.config import ModelProfile, Settings
from ash.core.errors import ConfigurationError
from ash.providers.base import ModelProvider
from ash.providers.mock import build_mock
from ash.providers.nemotron import NemotronProvider, SovereignProvider
from ash.providers.openai_compat import OpenAICompatibleProvider

ProviderFactory = Callable[[ModelProfile], ModelProvider]

_FACTORIES: dict[str, ProviderFactory] = {
    "mock": lambda p: build_mock(p.model),
    "openai_compatible": lambda p: OpenAICompatibleProvider(p),
    "nemotron": lambda p: NemotronProvider(p),
    "sovereign": lambda p: SovereignProvider(p),
}


def register_provider(kind: str, factory: ProviderFactory) -> None:
    """Extension point: register a new provider kind at import time."""
    _FACTORIES[kind] = factory


class ModelRouter:
    def __init__(self, profiles: dict[str, ModelProfile], default: str):
        if default not in profiles:
            raise ConfigurationError(f"default model profile '{default}' not defined (have {sorted(profiles)})")
        self._profiles = profiles
        self._default = default
        self._instances: dict[str, ModelProvider] = {}

    @classmethod
    def from_settings(cls, settings: Settings) -> ModelRouter:
        return cls(settings.model_profiles(), settings.default_model_profile)

    @property
    def profiles(self) -> dict[str, ModelProfile]:
        return dict(self._profiles)

    def get(self, profile: str | None = None) -> ModelProvider:
        name = profile or self._default
        if name not in self._profiles:
            raise ConfigurationError(f"unknown model profile '{name}'")
        if name not in self._instances:
            p = self._profiles[name]
            factory = _FACTORIES.get(p.provider)
            if factory is None:
                raise ConfigurationError(f"unknown provider kind '{p.provider}' for profile '{name}'")
            self._instances[name] = factory(p)
        return self._instances[name]

    def override(self, profile: str, provider: ModelProvider) -> None:
        """Inject a provider instance (tests, or a pre-built sovereign client)."""
        self._profiles.setdefault(profile, ModelProfile(name=profile, provider="custom", model=provider.model))
        self._instances[profile] = provider

    def health(self) -> dict[str, bool]:
        return {name: self.get(name).healthcheck() for name in self._profiles}
