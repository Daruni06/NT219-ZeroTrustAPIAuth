"""Negative tests for the ext_authz service.

Run this after Keycloak, Redis, OPA, and authz are running.
The tests call authz directly; backend services are not required.
"""

from __future__ import annotations

import httpx

from client import (
    ADMIN_SERVICE_URL,
    AUTHZ_VERIFY_URL,
    USER_SERVICE_URL,
    create_dpop_proof,
    generate_ed25519_key,
    get_access_token,
    verify_with_authz,
)


def print_result(name: str, expected: str, response: httpx.Response) -> None:
    print(f"\n[{name}]")
    print("Expected:", expected)
    print("Status:", response.status_code)
    print("Body:", response.text)


def print_replay_result(first: httpx.Response, second: httpx.Response) -> None:
    print("\n[REPLAY SAME DPOP JTI]")
    print("Expected: first request 200, second request 401")
    print("First status:", first.status_code)
    print("First body:", first.text)
    print("Second status:", second.status_code)
    print("Second body:", second.text)


def verify_without_dpop(access_token: str) -> httpx.Response:
    body = {
        "method": "GET",
        "path": "/users",
        "url": f"{USER_SERVICE_URL}/users",
        "headers": {
            "authorization": f"Bearer {access_token}",
        },
    }
    return httpx.post(AUTHZ_VERIFY_URL, json=body, timeout=10)


def verify_with_wrong_key(access_token: str) -> httpx.Response:
    wrong_private_key, wrong_public_jwk = generate_ed25519_key()
    return verify_with_authz(
        private_key=wrong_private_key,
        public_jwk=wrong_public_jwk,
        access_token=access_token,
        method="GET",
        path="/users",
        url=f"{USER_SERVICE_URL}/users",
    )


def verify_replay(private_key, public_jwk: dict, access_token: str) -> tuple[httpx.Response, httpx.Response]:
    dpop = create_dpop_proof(
        private_key=private_key,
        public_jwk=public_jwk,
        method="GET",
        url=f"{USER_SERVICE_URL}/users",
        access_token=access_token,
    )
    body = {
        "method": "GET",
        "path": "/users",
        "url": f"{USER_SERVICE_URL}/users",
        "headers": {
            "authorization": f"Bearer {access_token}",
            "dpop": dpop,
        },
    }
    first = httpx.post(AUTHZ_VERIFY_URL, json=body, timeout=10)
    second = httpx.post(AUTHZ_VERIFY_URL, json=body, timeout=10)
    return first, second


def main() -> None:
    print("Generating Ed25519 DPoP key for Alice")
    alice_private_key, alice_public_jwk = generate_ed25519_key()

    alice_token = get_access_token(
        private_key=alice_private_key,
        public_jwk=alice_public_jwk,
        username="alice",
        password="alice123",
    )

    baseline = verify_with_authz(
        private_key=alice_private_key,
        public_jwk=alice_public_jwk,
        access_token=alice_token,
        method="GET",
        path="/users",
        url=f"{USER_SERVICE_URL}/users",
    )
    print_result("BASELINE VALID REQUEST", "200 allow=true", baseline)

    missing_dpop = verify_without_dpop(alice_token)
    print_result("MISSING DPOP", "401 missing DPoP proof", missing_dpop)

    wrong_key = verify_with_wrong_key(alice_token)
    print_result("WRONG DPOP KEY", "401 DPoP key does not match token cnf", wrong_key)

    first_replay, second_replay = verify_replay(alice_private_key, alice_public_jwk, alice_token)
    print_replay_result(first_replay, second_replay)

    opa_deny = verify_with_authz(
        private_key=alice_private_key,
        public_jwk=alice_public_jwk,
        access_token=alice_token,
        method="GET",
        path="/admin/users",
        url=f"{ADMIN_SERVICE_URL}/admin/users",
    )
    print_result("OPA DENY USER ADMIN PATH", "403 OPA denied request", opa_deny)


if __name__ == "__main__":
    main()
