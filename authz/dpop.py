"""DPoP proof verification helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt

from .config import DPoPConfig


class DPoPVerificationError(ValueError):
    """Raised when DPoP proof verification fails."""


@dataclass(frozen=True)
class VerifiedDPoP:
    jti: str
    htm: str
    htu: str
    iat: int
    jwk: dict[str, Any]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def access_token_hash(access_token: str) -> str:
    return _b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise DPoPVerificationError("DPoP jwk must be OKP Ed25519")

    members = {"crv": jwk.get("crv"), "kty": jwk.get("kty"), "x": jwk.get("x")}

    if any(value is None for value in members.values()):
        raise DPoPVerificationError("incomplete DPoP jwk")

    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(hashlib.sha256(canonical).digest())


def _normalize_uri(uri: str) -> str:
    parsed = urlsplit(uri)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    return urlunsplit((scheme, netloc, parsed.path or "/", "", ""))


def _cnf_matches(cnf: dict[str, Any], proof_jwk: dict[str, Any]) -> bool:
    if "jwk" in cnf and isinstance(cnf["jwk"], dict):
        return jwk_thumbprint(cnf["jwk"]) == jwk_thumbprint(proof_jwk)
    if "jkt" in cnf:
        return cnf["jkt"] == jwk_thumbprint(proof_jwk)
    return False


def verify_dpop(
    proof: str,
    access_token: str,
    method: str,
    url: str,
    token_cnf: dict[str, Any],
    config: DPoPConfig,
) -> VerifiedDPoP:
    if not proof:
        raise DPoPVerificationError("missing DPoP proof")

    try:
        header = jwt.get_unverified_header(proof)
    except Exception as exc:
        raise DPoPVerificationError(f"invalid DPoP header: {exc}") from exc

    if header.get("typ") != "dpop+jwt":
        raise DPoPVerificationError("DPoP typ must be dpop+jwt")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPVerificationError("missing DPoP jwk")

    if not _cnf_matches(token_cnf, jwk):
        raise DPoPVerificationError("DPoP key does not match token cnf")

    try:
        public_key = jwt.algorithms.get_default_algorithms()[header["alg"]].from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            proof,
            public_key,
            algorithms=[header["alg"]],
            options={"verify_aud": False, "verify_iss": False},
        )
    except Exception as exc:
        raise DPoPVerificationError(f"invalid DPoP signature: {exc}") from exc

    htm = str(claims.get("htm", "")).upper()
    htu = str(claims.get("htu", ""))
    jti = str(claims.get("jti", ""))
    iat = claims.get("iat")

    if htm != method.upper():
        raise DPoPVerificationError("DPoP htm does not match request method")
    if _normalize_uri(htu) != _normalize_uri(url):
        raise DPoPVerificationError("DPoP htu does not match request url")
    if not jti:
        raise DPoPVerificationError("missing DPoP jti")
    if not isinstance(iat, int):
        raise DPoPVerificationError("missing or invalid DPoP iat")

    now = int(time.time())
    if abs(now - iat) > config.proof_lifetime_seconds + config.max_clock_skew_seconds:
        raise DPoPVerificationError("DPoP proof expired or issued too far in future")

    if config.require_ath and claims.get("ath") != access_token_hash(access_token):
        raise DPoPVerificationError("DPoP ath does not match access token")

    return VerifiedDPoP(jti=jti, htm=htm, htu=htu, iat=iat, jwk=jwk)
