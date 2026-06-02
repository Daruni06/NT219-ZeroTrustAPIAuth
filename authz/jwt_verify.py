"""JWT verification helpers."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from .config import KeycloakConfig


class JWTVerificationError(ValueError):
    """Raised when access token verification fails."""


@dataclass
class VerifiedToken:
    claims: dict[str, Any]
    subject: str
    username: str
    roles: list[str]
    scopes: list[str]
    cnf: dict[str, Any]


class JWTVerifier:
    def __init__(self, config: KeycloakConfig) -> None:
        self.config = config
        self._jwks_client = PyJWKClient(config.jwks_url)
        self._jwks_checked_at = 0.0

    def verify(self, token: str) -> VerifiedToken:
        if not token:
            raise JWTVerificationError("missing bearer token")

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=self.config.algorithms,
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except Exception as exc:
            raise JWTVerificationError(f"invalid access token: {exc}") from exc

        roles = claims.get("realm_access", {}).get("roles", [])
        if not isinstance(roles, list):
            roles = []

        scope_value = claims.get("scope", "")
        scopes = scope_value.split() if isinstance(scope_value, str) else []

        cnf = claims.get("cnf", {})
        if not isinstance(cnf, dict):
            cnf = {}

        return VerifiedToken(
            claims=claims,
            subject=str(claims.get("sub", "")),
            username=str(claims.get("preferred_username") or claims.get("email") or claims.get("sub", "")),
            roles=[str(role) for role in roles],
            scopes=[str(scope) for scope in scopes],
            cnf=cnf,
        )

    async def healthcheck(self) -> bool:
        if time.time() - self._jwks_checked_at < self.config.jwks_cache_seconds:
            return True
        async with httpx.AsyncClient(timeout=2) as client:
            response = await client.get(self.config.jwks_url)
            response.raise_for_status()
        self._jwks_checked_at = time.time()
        return True
