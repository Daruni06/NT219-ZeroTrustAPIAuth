"""Verify backend services are not reachable directly from the VPS host."""

from __future__ import annotations

import httpx


DIRECT_BACKEND_URLS = [
    "http://127.0.0.1:8001/users",
    "http://127.0.0.1:8002/resources",
    "http://127.0.0.1:8003/admin/users",
]


def main() -> None:
    print("Direct backend bypass test")
    print("Expected: connection refused/unreachable for every backend URL")

    for url in DIRECT_BACKEND_URLS:
        print(f"\n[BYPASS] GET {url}")
        try:
            response = httpx.get(url, timeout=3)
        except httpx.ConnectError as exc:
            print("Status: blocked")
            print(f"Body: backend not reachable directly ({exc})")
            continue

        print("Status:", response.status_code)
        print("Body:", response.text)
        print("Result: unexpected direct access; check docker-compose port publishing")


if __name__ == "__main__":
    main()
