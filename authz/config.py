"""Configuration loading for the ext_authz service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int


@dataclass(frozen=True)
class KeycloakConfig:
    issuer: str
    jwks_url: str
    audience: str
    algorithms: list[str]
    jwks_cache_seconds: int


@dataclass(frozen=True)
class DPoPConfig:
    required: bool
    max_clock_skew_seconds: int
    proof_lifetime_seconds: int
    require_ath: bool


@dataclass(frozen=True)
class RedisConfig:
    url: str
    password: str
    replay_prefix: str
    replay_ttl_seconds: int


@dataclass(frozen=True)
class OPAConfig:
    decision_url: str
    timeout_seconds: float


@dataclass(frozen=True)
class AuthzConfig:
    fail_closed: bool
    forwarded_identity_headers: dict[str, str]


@dataclass(frozen=True)
class LoggingConfig:
    level: str


@dataclass(frozen=True)
class Settings:
    server: ServerConfig
    keycloak: KeycloakConfig
    dpop: DPoPConfig
    redis: RedisConfig
    opa: OPAConfig
    authz: AuthzConfig
    logging: LoggingConfig


def _as_bool(value: str | bool | None, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError("config root must be a mapping")
    return data


def load_settings(path: str | Path | None = None) -> Settings:
    config_path = path or os.getenv("AUTHZ_CONFIG_PATH", "authz/config.yaml")
    raw = _load_yaml(config_path)

    server = raw.get("server", {})
    keycloak = raw.get("keycloak", {})
    dpop = raw.get("dpop", {})
    redis = raw.get("redis", {})
    opa = raw.get("opa", {})
    authz = raw.get("authz", {})
    logging = raw.get("logging", {})

    return Settings(
        server=ServerConfig(
            host=os.getenv("AUTHZ_HOST", server.get("host", "0.0.0.0")),
            port=int(os.getenv("AUTHZ_PORT", server.get("port", 8090))),
        ),
        keycloak=KeycloakConfig(
            issuer=os.getenv("KEYCLOAK_ISSUER", keycloak["issuer"]),
            jwks_url=os.getenv("KEYCLOAK_JWKS_URL", keycloak["jwks_url"]),
            audience=os.getenv("KEYCLOAK_AUDIENCE", keycloak["audience"]),
            algorithms=list(keycloak.get("algorithms", ["RS256"])),
            jwks_cache_seconds=int(keycloak.get("jwks_cache_seconds", 300)),
        ),
        dpop=DPoPConfig(
            required=_as_bool(os.getenv("DPOP_REQUIRED"), bool(dpop.get("required", True))),
            max_clock_skew_seconds=int(
                os.getenv("DPOP_MAX_CLOCK_SKEW_SECONDS", dpop.get("max_clock_skew_seconds", 60))
            ),
            proof_lifetime_seconds=int(
                os.getenv("DPOP_PROOF_LIFETIME_SECONDS", dpop.get("proof_lifetime_seconds", 300))
            ),
            require_ath=bool(dpop.get("require_ath", True)),
        ),
        redis=RedisConfig(
            url=os.getenv("REDIS_URL", redis.get("url", "redis://localhost:6379/0")),
            password=os.getenv("REDIS_PASSWORD", redis.get("password", "")),
            replay_prefix=redis.get("replay_prefix", "dpop:jti:"),
            replay_ttl_seconds=int(redis.get("replay_ttl_seconds", 300)),
        ),
        opa=OPAConfig(
            decision_url=os.getenv("OPA_DECISION_URL", opa["decision_url"]),
            timeout_seconds=float(opa.get("timeout_seconds", 2)),
        ),
        authz=AuthzConfig(
            fail_closed=bool(authz.get("fail_closed", True)),
            forwarded_identity_headers=dict(authz.get("forwarded_identity_headers", {})),
        ),
        logging=LoggingConfig(level=os.getenv("LOG_LEVEL", logging.get("level", "INFO"))),
    )
