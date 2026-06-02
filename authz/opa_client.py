"""OPA client helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .config import OPAConfig


class OPADecisionError(RuntimeError):
    """Raised when OPA cannot return a usable decision."""


@dataclass(frozen=True)
class OPADecision:
    allow: bool
    raw: dict[str, Any]


class OPAClient:
    def __init__(self, config: OPAConfig) -> None:
        self.config = config

    async def authorize(
        self,
        *,
        user_id: str,
        username: str,
        roles: list[str],
        scopes: list[str],
        method: str,
        path: str,
    ) -> OPADecision:
        payload = {
            "input": {
                "user_id": user_id,
                "username": username,
                "roles": roles,
                "scopes": scopes,
                "method": method.upper(),
                "path": path,
            }
        }
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self.config.decision_url, json=payload)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            raise OPADecisionError(f"OPA request failed: {exc}") from exc

        result = data.get("result")
        if not isinstance(result, bool):
            raise OPADecisionError("OPA response missing boolean result")

        return OPADecision(allow=result, raw=data)
