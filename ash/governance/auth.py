"""Authentication: JWT bearer tokens for humans, static API keys for services.

Passwords are stored as PBKDF2-SHA256 hashes. Users come from a YAML file
(``ASH_USERS_FILE``) or, for development only, a bootstrap admin.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Any

import jwt
import yaml

from ash.config import Settings
from ash.core.errors import AuthenticationError, ConfigurationError
from ash.core.types import Principal

_PBKDF2_ITER = 200_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITER)
    return "pbkdf2$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITER)
    return hmac.compare_digest(dk, expected)


@dataclass
class User:
    username: str
    password_hash: str
    roles: list[str]
    disabled: bool = False


class AuthService:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._users: dict[str, User] = {}
        self._api_keys: dict[str, Principal] = {}
        self._load_users()
        self._load_api_keys()

    # ------------------------------------------------------------------ #
    def _load_users(self) -> None:
        if self._settings.users_file:
            with open(self._settings.users_file, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            for u in data.get("users", []):
                self._users[u["username"]] = User(
                    username=u["username"],
                    password_hash=u["password_hash"],
                    roles=list(u.get("roles", [])),
                    disabled=bool(u.get("disabled")),
                )
        if self._settings.bootstrap_admin_password:
            if self._settings.is_production():
                raise ConfigurationError("bootstrap admin is not allowed in production")
            self._users.setdefault(
                "admin", User("admin", hash_password(self._settings.bootstrap_admin_password), ["admin"])
            )

    def _load_api_keys(self) -> None:
        raw = self._settings.api_keys.strip()
        if not raw:
            return
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            if len(parts) != 3:
                raise ConfigurationError("ASH_API_KEYS entries must be key:name:role1|role2")
            key, name, roles = parts
            self._api_keys[key] = Principal(
                id=f"svc:{name}", name=name, kind="service", roles=[r for r in roles.split("|") if r]
            )

    # ------------------------------------------------------------------ #
    def add_user(self, username: str, password: str, roles: list[str]) -> User:
        u = User(username, hash_password(password), roles)
        self._users[username] = u
        return u

    def add_api_key(self, key: str, principal: Principal) -> None:
        self._api_keys[key] = principal

    def authenticate_password(self, username: str, password: str) -> Principal:
        u = self._users.get(username)
        if not u or u.disabled or not verify_password(password, u.password_hash):
            raise AuthenticationError("invalid credentials")
        return Principal(id=f"user:{u.username}", name=u.username, kind="user", roles=list(u.roles))

    def issue_token(self, principal: Principal) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self._settings.jwt_issuer,
            "sub": principal.id,
            "name": principal.name,
            "kind": principal.kind,
            "roles": principal.roles,
            "iat": now,
            "exp": now + self._settings.jwt_ttl_seconds,
        }
        return jwt.encode(claims, self._settings.jwt_secret, algorithm="HS256")

    def principal_from_token(self, token: str) -> Principal:
        try:
            claims = jwt.decode(
                token, self._settings.jwt_secret, algorithms=["HS256"], issuer=self._settings.jwt_issuer
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid token: {exc}") from exc
        return Principal(
            id=claims["sub"],
            name=claims.get("name", claims["sub"]),
            kind=claims.get("kind", "user"),
            roles=list(claims.get("roles", [])),
        )

    def principal_from_api_key(self, key: str) -> Principal:
        for k, p in self._api_keys.items():
            if hmac.compare_digest(k, key):
                return p
        raise AuthenticationError("invalid api key")
