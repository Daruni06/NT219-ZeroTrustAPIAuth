"""Print commands for verifying backend mTLS from the Docker network."""

from __future__ import annotations


COMMANDS = [
    (
        "Envoy client cert should succeed",
        "docker compose exec envoy openssl s_client "
        "-connect user-service:8000 "
        "-servername user-service "
        "-CAfile /etc/envoy/certs/ca.crt "
        "-cert /etc/envoy/certs/envoy-client.crt "
        "-key /etc/envoy/certs/envoy-client.key "
        "-brief",
    ),
    (
        "No client cert should fail",
        "docker compose exec envoy openssl s_client "
        "-connect user-service:8000 "
        "-servername user-service "
        "-CAfile /etc/envoy/certs/ca.crt "
        "-brief",
    ),
]


def main() -> None:
    print("Run these on the VPS after pki/setup-pki.sh and docker compose up -d --build:")
    for title, command in COMMANDS:
        print(f"\n[{title}]")
        print(command)


if __name__ == "__main__":
    main()
