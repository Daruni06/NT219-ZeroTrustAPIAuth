# Phân Tích Security Và Crypto

## Câu Hỏi Trung Tâm

Nếu attacker đánh cắp được access token hợp lệ, làm sao hệ thống phát hiện attacker không phải chủ token?

Đáp án của project: token không còn là bearer token thuần. Token được ràng buộc với public key của client qua DPoP. Khi gọi API, client phải ký DPoP proof bằng private key tương ứng. Attacker có token nhưng không có private key sẽ bị deny.

## Threat 1: Token Theft

**Rủi ro:** Attacker lấy được access token từ log, browser storage, proxy, máy người dùng hoặc network dump.

**Cơ chế chặn:**

- Client sinh Ed25519 key pair.
- Keycloak cấp token có `cnf.jkt`.
- Mỗi request có DPoP proof ký bằng private key.
- `authz` so khớp key trong proof với `cnf.jkt`.

**Expected demo:**

```text
Token hợp lệ + DPoP proof đúng key -> allow
Token hợp lệ + DPoP proof key khác -> 401
```

## Threat 2: Replay Attack

**Rủi ro:** Attacker bắt được một request hợp lệ rồi gửi lại.

**Cơ chế chặn:**

- DPoP proof có `jti` duy nhất.
- `authz` lưu `jti` vào Redis với TTL.
- Nếu cùng `jti` xuất hiện lại, request bị reject.

**Expected demo:**

```text
Request 1 với DPoP jti X -> allow
Request 2 dùng lại proof jti X -> 401 replay detected
```

## Threat 3: Unauthorized Access

**Rủi ro:** User thường gọi endpoint admin.

**Cơ chế chặn:**

- OPA policy deny-by-default.
- Rule `/admin/*` chỉ allow role `admin`.

**Expected demo:**

```text
Alice GET /admin/users -> 403
Admin GET /admin/users -> 200
```

## Threat 4: Gateway Bypass

**Rủi ro:** Attacker gọi thẳng backend, bỏ qua authz.

**Cơ chế chặn:**

- Backend không publish port ra host.
- Envoy là entry point.
- Envoy gọi backend bằng mTLS nội bộ.

**Expected demo:**

```text
GET http://127.0.0.1:8001/users -> connection refused
GET http://127.0.0.1:10000/users + valid token/proof -> route qua Gateway
```

## Public Key Distribution

| Public key | Ai sở hữu | Phân phối bằng cách nào | Ai verify |
|---|---|---|---|
| Client DPoP public key | Demo Client | Key thumbprint nằm trong token `cnf.jkt` | `authz` |
| Keycloak signing public key | Keycloak | JWKS endpoint | `authz` |
| Internal CA certificate | PKI/Vault | Mount vào Envoy/backend | TLS stack |

## Vì Sao Dùng Các Cơ Chế Này

- **DPoP:** biến bearer token thành proof-of-possession token.
- **Ed25519 cho DPoP:** key nhỏ, chữ ký nhanh, phù hợp demo crypto hiện đại.
- **Redis replay cache:** lưu `jti` ngắn hạn, đơn giản và rõ để demo replay defense.
- **OPA:** tách policy authorization khỏi code backend.
- **mTLS:** backend chỉ nhận request từ client có certificate hợp lệ.
- **Deny-by-default:** lỗi authz/OPA/replay đều không được allow ngầm.

## Giới Hạn Demo

- Hệ thống chạy trên một VPS, phân tách bằng Docker network thay vì nhiều subnet vật lý.
- Cert demo sinh bằng script để dễ chạy; Vault PKI dùng để minh họa vai trò cấp cert/TTL/rotation.
- Backend là service demo đơn giản, chưa phải production business logic.
- Website demo xử lý DPoP/token ở server-side để tránh phức tạp WebCrypto/OIDC browser flow. Khi có domain thật, browser -> website vẫn dùng HTTPS trusted certificate qua Caddy.
