from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx
import jwt
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "demo-client"))

from client import create_dpop_proof, generate_ed25519_key  # noqa: E402


REALM = os.getenv("KEYCLOAK_REALM", "zero-trust")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "demo-client")

KEYCLOAK_INTERNAL_BASE_URL = os.getenv("KEYCLOAK_INTERNAL_BASE_URL", "http://keycloak:8080")
KEYCLOAK_PUBLIC_BASE_URL = os.getenv("KEYCLOAK_PUBLIC_BASE_URL", "http://127.0.0.1:8080")

GATEWAY_INTERNAL_BASE_URL = os.getenv("GATEWAY_INTERNAL_BASE_URL", "http://envoy:10000")
GATEWAY_PUBLIC_BASE_URL = os.getenv("GATEWAY_PUBLIC_BASE_URL", "http://127.0.0.1:10000")

USERS = {
    "alice": "alice123",
    "admin": "admin123",
}

SESSIONS: dict[str, dict[str, Any]] = {}

app = FastAPI(title="Zero-Trust Demo Web")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


class LoginRequest(BaseModel):
    username: str
    password: str


class ApiCallRequest(BaseModel):
    session_id: str
    method: str = "GET"
    path: str
    attack: str | None = None


def _host_header(url: str) -> str:
    parsed = httpx.URL(url)
    if parsed.port:
        return f"{parsed.host}:{parsed.port}"
    return parsed.host or ""


def _decode_token(access_token: str) -> dict[str, Any]:
    return jwt.decode(access_token, options={"verify_signature": False})


async def _get_access_token(private_key, public_jwk: dict, username: str, password: str) -> str:
    public_token_url = f"{KEYCLOAK_PUBLIC_BASE_URL}/realms/{REALM}/protocol/openid-connect/token"
    internal_token_url = f"{KEYCLOAK_INTERNAL_BASE_URL}/realms/{REALM}/protocol/openid-connect/token"

    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password,
        "scope": "openid profile email roles",
    }

    dpop_nonce = None
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        for _ in range(5):
            dpop = create_dpop_proof(
                private_key=private_key,
                public_jwk=public_jwk,
                method="POST",
                url=public_token_url,
                nonce=dpop_nonce,
            )
            response = await client.post(
                internal_token_url,
                data=data,
                headers={
                    "DPoP": dpop,
                    "Host": _host_header(KEYCLOAK_PUBLIC_BASE_URL),
                    "Connection": "close",
                },
            )
            nonce = response.headers.get("DPoP-Nonce")
            if nonce:
                dpop_nonce = nonce
            if response.status_code in {400, 401} and "use_dpop_nonce" in response.text and dpop_nonce:
                continue
            if response.status_code >= 400:
                raise HTTPException(status_code=502, detail=response.text)
            return response.json()["access_token"]

    raise HTTPException(status_code=502, detail="Keycloak token request failed")


async def _gateway_request(session: dict[str, Any], method: str, path: str, attack: str | None) -> dict[str, Any]:
    public_url = f"{GATEWAY_PUBLIC_BASE_URL}{path}"
    internal_url = f"{GATEWAY_INTERNAL_BASE_URL}{path}"
    access_token = session["access_token"]
    private_key = session["private_key"]
    public_jwk = session["public_jwk"]

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Host": _host_header(GATEWAY_PUBLIC_BASE_URL),
    }

    if attack == "missing_dpop":
        pass
    elif attack == "wrong_key":
        wrong_private_key, wrong_public_jwk = generate_ed25519_key()
        headers["DPoP"] = create_dpop_proof(
            wrong_private_key,
            wrong_public_jwk,
            method,
            public_url,
            access_token,
        )
    else:
        headers["DPoP"] = create_dpop_proof(
            private_key,
            public_jwk,
            method,
            public_url,
            access_token,
        )

    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        first = await client.request(method, internal_url, headers=headers)
        result = {
            "status": first.status_code,
            "body": first.text,
        }

        if attack == "replay":
            second = await client.request(method, internal_url, headers=headers)
            result["replay_second"] = {
                "status": second.status_code,
                "body": second.text,
            }

        return result


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/login")
async def login(request: LoginRequest) -> dict[str, Any]:
    if USERS.get(request.username) != request.password:
        raise HTTPException(status_code=401, detail="invalid demo credentials")

    private_key, public_jwk = generate_ed25519_key()
    access_token = await _get_access_token(private_key, public_jwk, request.username, request.password)
    claims = _decode_token(access_token)
    session_id = str(uuid.uuid4())

    SESSIONS[session_id] = {
        "private_key": private_key,
        "public_jwk": public_jwk,
        "access_token": access_token,
        "claims": claims,
    }

    return {
        "session_id": session_id,
        "public_jwk": public_jwk,
        "claims": claims,
    }


@app.post("/api/call")
async def call_api(request: ApiCallRequest) -> dict[str, Any]:
    session = SESSIONS.get(request.session_id)
    if not session:
        raise HTTPException(status_code=401, detail="login first")

    result = await _gateway_request(session, request.method.upper(), request.path, request.attack)
    return {
        "request": {
            "method": request.method.upper(),
            "path": request.path,
            "attack": request.attack,
        },
        "result": result,
    }
