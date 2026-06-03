# Kiến Trúc Hệ Thống

## Tổng Quan

Hệ thống mô phỏng Zero-Trust API Authentication trên một VPS. Mọi request từ client phải đi qua Envoy Gateway, được service `authz` kiểm tra trước khi forward sang backend.

```text
Demo Client
  |
  | HTTP + Authorization Bearer token + DPoP proof
  v
Envoy Gateway
  |
  | ext_authz check
  v
authz FastAPI
  |-- verify JWT qua JWKS của Keycloak
  |-- verify DPoP proof bằng public key binding trong token cnf
  |-- check replay jti qua Redis
  |-- hỏi OPA policy
  v
Envoy Gateway
  |
  | mTLS nội bộ + identity headers
  v
Backend Services
```

## Các Node

| Node | Thành phần | Vai trò |
|---|---|---|
| 1 | Demo Client | Sinh Ed25519 DPoP key, lấy token, tạo DPoP proof, gọi API |
| 2 | Envoy Gateway | Entry point, gọi ext_authz, route backend, fail-closed |
| 3 | Keycloak | Identity Provider, cấp access token, publish JWKS |
| 4 | authz service | Verify JWT, DPoP, replay, OPA decision |
| 5 | OPA | Policy engine, deny-by-default |
| 6 | Redis | Replay cache cho DPoP `jti` |
| 7 | Backend services | User, Resource, Admin APIs |
| 8 | PKI/Vault | Cấp/chứng minh certificate nội bộ cho mTLS |

## Luồng Cấp Token

1. Client sinh Ed25519 key pair.
2. Client tạo DPoP proof cho token endpoint.
3. Client gửi request lấy token tới Keycloak.
4. Keycloak cấp access token có claim `cnf.jkt`, ràng buộc token với public key của client.
5. Client giữ private key, không gửi private key lên server.

## Luồng Gọi API

1. Client gọi Envoy Gateway với:
   - `Authorization: Bearer <access_token>`
   - `DPoP: <proof>`
2. Envoy gọi `authz` trước khi route.
3. `authz` verify:
   - chữ ký JWT qua JWKS
   - issuer/audience/token expiry
   - DPoP signature
   - DPoP `htu`, `htm`, `ath`
   - DPoP key match với `cnf.jkt`
   - `jti` chưa replay qua Redis
4. `authz` hỏi OPA.
5. Nếu allow, Envoy forward sang backend bằng mTLS và inject identity headers:
   - `x-user-id`
   - `x-user-name`
   - `x-user-roles`
   - `x-scopes`
6. Nếu deny/error, Gateway trả 401/403/503 và không gọi backend.

## Trust Boundaries

| Boundary | Không tin mặc định | Cơ chế kiểm soát |
|---|---|---|
| Internet -> Gateway | Client/token có thể bị giả mạo | JWT + DPoP |
| Gateway -> authz | Authz phải fail-closed | Envoy ext_authz |
| authz -> OPA/Redis/Keycloak | Dependency có thể lỗi | timeout + deny |
| Gateway -> Backend | Không cho gọi thẳng backend | Docker network + mTLS |
| Backend | Không tự verify token | Chỉ tin headers từ Gateway |

## Ghi Chú Triển Khai

- Backend không publish port trực tiếp ra host.
- Keycloak/OPA/Redis/authz chỉ bind localhost trong demo.
- Gateway là entry point cho API.
- mTLS demo dùng cert sinh bởi `pki/setup-pki.sh`.
- Vault PKI được dùng để minh họa cơ chế cấp cert/role/TTL; demo Compose hiện dùng cert file sinh sẵn để dễ chạy.
- Demo website có thể host trên cùng VPS bằng Caddy. Caddy terminate HTTPS public bằng Let's Encrypt, rồi reverse proxy vào `demo-web`.
