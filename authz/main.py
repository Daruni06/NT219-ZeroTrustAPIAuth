"""FastAPI ext_authz service entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .config import Settings, load_settings
from .dpop import DPoPVerificationError, verify_dpop
from .jwt_verify import JWTVerificationError, JWTVerifier
from .opa_client import OPAClient, OPADecisionError
from .replay_cache import ReplayCache, ReplayDetectedError


settings: Settings = load_settings()
logging.basicConfig(level=settings.logging.level)
logger = logging.getLogger("authz")


class VerifyRequest(BaseModel):
    method: str = Field(..., examples=["GET"])
    path: str = Field(..., examples=["/users"])
    url: str | None = Field(None, examples=["https://api.example.test/users"])
    headers: dict[str, str] = Field(default_factory=dict)


class VerifyResponse(BaseModel):
    allow: bool
    reason: str
    headers: dict[str, str] = Field(default_factory=dict)


def _bearer_token(value: str | None) -> str:
    if not value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing Authorization header")
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid Authorization header")
    return token


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = {key.lower(): value for key, value in headers.items()}
    return lowered.get(name.lower())


def _request_url(request: Request, body: VerifyRequest) -> str:
    if body.url:
        return body.url
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    proto = request.headers.get("x-forwarded-proto", "http")
    return f"{proto}://{host}{body.path}"


async def _authorize_request(
    *,
    request: Request,
    access_token: str,
    dpop_proof: str | None,
    method: str,
    path: str,
    url: str,
) -> dict[str, str]:
    verified_token = request.app.state.jwt_verifier.verify(access_token)

    if settings.dpop.required:
        verified_dpop = verify_dpop(
            proof=dpop_proof or "",
            access_token=access_token,
            method=method,
            url=url,
            token_cnf=verified_token.cnf,
            config=settings.dpop,
        )
        await request.app.state.replay_cache.check_and_store(verified_dpop.jti)

    decision = await request.app.state.opa_client.authorize(
        user_id=verified_token.subject,
        username=verified_token.username,
        roles=verified_token.roles,
        scopes=verified_token.scopes,
        method=method,
        path=path,
    )

    if not decision.allow:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="OPA denied request")

    header_names = settings.authz.forwarded_identity_headers
    return {
        header_names.get("user_id", "x-user-id"): verified_token.subject,
        header_names.get("username", "x-user-name"): verified_token.username,
        header_names.get("roles", "x-user-roles"): ",".join(verified_token.roles),
        header_names.get("scopes", "x-scopes"): " ".join(verified_token.scopes),
    }


def _handle_authz_error(exc: Exception) -> None:
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, (JWTVerificationError, DPoPVerificationError, ReplayDetectedError)):
        logger.info("deny: %s", exc)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    if isinstance(exc, OPADecisionError):
        logger.error("OPA failure: %s", exc)
        code = status.HTTP_403_FORBIDDEN if settings.authz.fail_closed else status.HTTP_200_OK
        raise HTTPException(status_code=code, detail="authorization service unavailable") from exc
    raise exc


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.jwt_verifier = JWTVerifier(settings.keycloak)
    app.state.replay_cache = ReplayCache(settings.redis)
    app.state.opa_client = OPAClient(settings.opa)
    yield
    await app.state.replay_cache.close()


app = FastAPI(title="Zero-Trust ext_authz", version="0.1.0", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/verify", response_model=VerifyResponse)
async def verify(
    body: VerifyRequest,
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    dpop_header: Annotated[str | None, Header(alias="DPoP")] = None,
) -> VerifyResponse:
    auth_header = authorization or _header(body.headers, "authorization")
    dpop_proof = dpop_header or _header(body.headers, "dpop")

    try:
        access_token = _bearer_token(auth_header)
        identity_headers = await _authorize_request(
            request=request,
            access_token=access_token,
            dpop_proof=dpop_proof,
            method=body.method,
            path=body.path,
            url=_request_url(request, body),
        )
    except Exception as exc:
        _handle_authz_error(exc)

    return VerifyResponse(
        allow=True,
        reason="allowed",
        headers=identity_headers,
    )


@app.api_route(
    "/envoy/authz/{original_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def verify_for_envoy(
    original_path: str,
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    dpop_header: Annotated[str | None, Header(alias="DPoP")] = None,
) -> Response:
    path = f"/{original_path}"
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    proto = request.headers.get("x-forwarded-proto", "http")
    url = f"{proto}://{host}{path}"

    try:
        access_token = _bearer_token(authorization)
        identity_headers = await _authorize_request(
            request=request,
            access_token=access_token,
            dpop_proof=dpop_header,
            method=request.method,
            path=path,
            url=url,
        )
    except Exception as exc:
        _handle_authz_error(exc)

    return Response(status_code=status.HTTP_200_OK, headers=identity_headers)
