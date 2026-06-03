"""Negative tests through Envoy Gateway.

Run after Keycloak, Redis, OPA, authz, Envoy, and backend services are running.
These tests exercise the public entrypoint instead of calling authz directly.
"""

from __future__ import annotations

import httpx

from client import create_dpop_proof, generate_ed25519_key, get_access_token


GATEWAY_URL = "http://127.0.0.1:10000"


def print_result(name: str, expected: str, response: httpx.Response) -> None:
    print(f"\n[{name}]")
    print("Expected:", expected)
    print("Status:", response.status_code)
    print("Body:", response.text)


def gateway_request(
    *,
    method: str,
    path: str,
    access_token: str | None = None,
    dpop: str | None = None,
) -> httpx.Response:
    headers = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if dpop:
        headers["DPoP"] = dpop

    return httpx.request(method, f"{GATEWAY_URL}{path}", headers=headers, timeout=10)


def test_valid_user_request(private_key, public_jwk: dict, access_token: str) -> httpx.Response:
    path = "/users"
    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method="GET",
        url=f"{GATEWAY_URL}{path}",
        access_token=access_token,
    )
    return gateway_request(method="GET", path=path, access_token=access_token, dpop=dpop)


def test_missing_dpop(access_token: str) -> httpx.Response:
    return gateway_request(method="GET", path="/users", access_token=access_token)


def test_wrong_dpop_key(access_token: str) -> httpx.Response:
    wrong_private_key, wrong_public_jwk = generate_ed25519_key()
    path = "/users"
    dpop = create_dpop_proof(
        private_key=wrong_private_key,
        public_jwk=wrong_public_jwk,
        method="GET",
        url=f"{GATEWAY_URL}{path}",
        access_token=access_token,
    )
    return gateway_request(method="GET", path=path, access_token=access_token, dpop=dpop)


def test_replay(private_key, public_jwk: dict, access_token: str) -> tuple[httpx.Response, httpx.Response]:
    path = "/users"
    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method="GET",
        url=f"{GATEWAY_URL}{path}",
        access_token=access_token,
    )
    first = gateway_request(method="GET", path=path, access_token=access_token, dpop=dpop)
    second = gateway_request(method="GET", path=path, access_token=access_token, dpop=dpop)
    return first, second


def test_opa_deny(private_key, public_jwk: dict, access_token: str) -> httpx.Response:
    path = "/admin/users"
    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method="GET",
        url=f"{GATEWAY_URL}{path}",
        access_token=access_token,
    )
    return gateway_request(method="GET", path=path, access_token=access_token, dpop=dpop)


def main() -> None:
    print("Generating Ed25519 DPoP key for Alice")
    private_key, public_jwk = generate_ed25519_key()
    access_token = get_access_token(
        private_key=private_key,
        public_jwk=public_jwk,
        username="alice",
        password="alice123",
    )

    baseline = test_valid_user_request(private_key, public_jwk, access_token)
    print_result("BASELINE VALID GATEWAY REQUEST", "200 backend response", baseline)

    missing_dpop = test_missing_dpop(access_token)
    print_result("MISSING DPOP THROUGH GATEWAY", "401 or 403 denied by ext_authz", missing_dpop)

    wrong_key = test_wrong_dpop_key(access_token)
    print_result("WRONG DPOP KEY THROUGH GATEWAY", "401 or 403 denied by ext_authz", wrong_key)

    first_replay, second_replay = test_replay(private_key, public_jwk, access_token)
    print("\n[REPLAY SAME DPOP JTI THROUGH GATEWAY]")
    print("Expected: first request 200, second request 401 or 403")
    print("First status:", first_replay.status_code)
    print("First body:", first_replay.text)
    print("Second status:", second_replay.status_code)
    print("Second body:", second_replay.text)

    opa_deny = test_opa_deny(private_key, public_jwk, access_token)
    print_result("OPA DENY THROUGH GATEWAY", "403 denied for alice on /admin/users", opa_deny)


if __name__ == "__main__":
    main()
