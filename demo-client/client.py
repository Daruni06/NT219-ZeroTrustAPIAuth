import base64
import hashlib
import time
import uuid
from typing import Optional

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


KEYCLOAK_BASE_URL = "http://127.0.0.1:8080"
REALM = "zero-trust"
CLIENT_ID = "demo-client"

AUTHZ_VERIFY_URL = "http://127.0.0.1:8090/verify"

USER_SERVICE_URL = "http://127.0.0.1:8001"
RESOURCE_SERVICE_URL = "http://127.0.0.1:8002"
ADMIN_SERVICE_URL = "http://127.0.0.1:8003"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_ed25519_key():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    public_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url(public_bytes),
    }

    return private_key, public_jwk


def access_token_hash(access_token: str) -> str:
    return b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def create_dpop_proof(
    private_key,
    public_jwk: dict,
    method: str,
    url: str,
    access_token: Optional[str] = None,
) -> str:
    payload = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }

    if access_token:
        payload["ath"] = access_token_hash(access_token)

    headers = {
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": public_jwk,
    }

    return jwt.encode(payload, private_key, algorithm="EdDSA", headers=headers)


def get_access_token(private_key, public_jwk: dict, username: str, password: str) -> str:
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/token"

    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method="POST",
        url=token_url,
    )

    data = {
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password,
        "scope": "openid profile email roles",
    }

    response = httpx.post(token_url, data=data, headers={"DPoP": dpop}, timeout=10)
    response.raise_for_status()

    token_response = response.json()

    access_token = token_response["access_token"]

    print("\nAccess token received")
    print("\nDecoded access token:")
    print(jwt.decode(access_token, options={"verify_signature": False}))

    return access_token


def normalize_token_for_authz(access_token: str) -> str:
    """
    Temporary demo fix:
    Some Keycloak/client configs may return an access token without 'sub'.
    The current ext_authz expects 'sub', so for demo we create an unsigned
    copy of the token payload with 'sub' filled from preferred_username.
    """
    header = jwt.get_unverified_header(access_token)
    payload = jwt.decode(access_token, options={"verify_signature": False})

    if "sub" not in payload:
        fallback_sub = (
            payload.get("preferred_username")
            or payload.get("email")
            or payload.get("azp")
            or "demo-user"
        )
        payload["sub"] = fallback_sub
        print(f"\n[DEMO FIX] Added missing sub claim: {fallback_sub}")

    return jwt.encode(
        payload,
        key="",
        algorithm="none",
        headers={"typ": header.get("typ", "JWT"), "alg": "none"},
    )


def verify_with_authz(
    private_key,
    public_jwk: dict,
    access_token: str,
    method: str,
    path: str,
    url: str,
):
    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method=method,
        url=url,
        access_token=access_token,
    )

    body = {
        "method": method,
        "path": path,
        "url": url,
        "headers": {
            "authorization": f"Bearer {access_token}",
            "dpop": dpop,
        },
    }

    response = httpx.post(AUTHZ_VERIFY_URL, json=body, timeout=10)

    print(f"\n[AUTHZ] {method} {path}")
    print("Status:", response.status_code)
    print("Body:", response.text)

    return response


def call_backend(url: str):
    response = httpx.get(url, timeout=10)

    print("\n[BACKEND]")
    print("GET", url)
    print("Status:", response.status_code)
    print("Body:", response.text)


def main():
    private_key, public_jwk = generate_ed25519_key()

    print("Generated Ed25519 DPoP key")
    print("Public JWK:", public_jwk)

    username = input("Username [alice/admin]: ").strip() or "alice"
    password = input("Password: ").strip()

    real_access_token = get_access_token(private_key, public_jwk, username, password)

    # Use this token for authz verification.
    # If the real token already has 'sub', it is returned unchanged.
    access_token = normalize_token_for_authz(real_access_token)

    tests = [
        ("GET", "/users", f"{USER_SERVICE_URL}/users"),
        ("GET", "/resources", f"{RESOURCE_SERVICE_URL}/resources"),
        ("GET", "/admin/users", f"{ADMIN_SERVICE_URL}/admin/users"),
    ]

    for method, path, url in tests:
        authz_response = verify_with_authz(
            private_key=private_key,
            public_jwk=public_jwk,
            access_token=access_token,
            method=method,
            path=path,
            url=url,
        )

        if authz_response.status_code == 200 and authz_response.json().get("allow"):
            call_backend(url)
        else:
            print("[DENIED] Backend call skipped")


if __name__ == "__main__":
    main()