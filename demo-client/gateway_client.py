"""Demo client that calls APIs through Envoy Gateway."""

from __future__ import annotations

import httpx

from client import create_dpop_proof, generate_ed25519_key, get_access_token


GATEWAY_URL = "http://127.0.0.1:10000"


def call_gateway(private_key, public_jwk: dict, access_token: str, method: str, path: str) -> None:
    url = f"{GATEWAY_URL}{path}"
    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method=method,
        url=url,
        access_token=access_token,
    )
    response = httpx.request(
        method,
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "DPoP": dpop,
        },
        timeout=10,
    )

    print(f"\n[GATEWAY] {method} {path}")
    print("Status:", response.status_code)
    print("Body:", response.text)


def main() -> None:
    private_key, public_jwk = generate_ed25519_key()

    print("Generated Ed25519 DPoP key")
    print("Public JWK:", public_jwk)

    username = input("Username [alice/admin]: ").strip() or "alice"
    password = input("Password: ").strip()

    access_token = get_access_token(private_key, public_jwk, username, password)

    tests = [
        ("GET", "/users"),
        ("GET", "/resources"),
        ("GET", "/admin/users"),
    ]

    for method, path in tests:
        call_gateway(private_key, public_jwk, access_token, method, path)


if __name__ == "__main__":
    main()
