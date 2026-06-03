# Dàn Ý Báo Cáo Và Thuyết Trình

## 1. Giới Thiệu Đề Tài

- Tên đề tài: Zero-Trust API Authentication.
- Bài toán: access token hợp lệ vẫn có thể bị đánh cắp.
- Câu hỏi chính: nếu attacker có token, làm sao biết hắn không phải chủ token?
- Mục tiêu: áp dụng cryptography vào xác thực API thực tế.

## 2. Threat Model

Trình bày 4 rủi ro:

1. Bearer token theft.
2. Replay attack.
3. Unauthorized access theo role.
4. Bypass Gateway gọi thẳng backend.

## 3. Kiến Trúc Hệ Thống

Các thành phần:

- Demo Client
- Envoy Gateway
- Keycloak
- authz FastAPI
- Redis
- OPA
- Backend services
- PKI/Vault

Luồng chính:

```text
Client -> Gateway -> authz -> OPA/Redis/Keycloak -> Gateway -> Backend
```

## 4. Cơ Chế Crypto

### DPoP

- Client sinh key pair.
- Token có `cnf.jkt`.
- Mỗi request có DPoP proof.
- `authz` verify proof và binding.

### Replay Protection

- DPoP proof có `jti`.
- Redis lưu `jti` đã dùng.
- Dùng lại proof bị deny.

### mTLS

- Backend yêu cầu client certificate.
- Envoy có cert client hợp lệ.
- Gọi thẳng backend không có cert/không route được.

### JWKS

- Keycloak publish public signing keys qua JWKS.
- `authz` fetch JWKS để verify JWT.

## 5. Authorization Policy

- OPA dùng Rego.
- Deny-by-default.
- User được `/users`, `/resources`.
- Admin được `/admin`.

## 6. Demo Script

Demo theo thứ tự:

1. Alice gọi `/users` và `/resources` thành công.
2. Alice gọi `/admin/users` bị deny.
3. Admin gọi `/admin/users` thành công.
4. Missing DPoP bị deny.
5. Wrong DPoP key bị deny.
6. Replay same `jti` bị deny.
7. Bypass Gateway bị chặn.
8. mTLS có cert pass, không cert fail.

## 7. Kết Quả

Bảng kết quả:

| Case | Expected | Result |
|---|---|---|
| Alice GET /users | Allow | Pass |
| Alice GET /admin/users | Deny | Pass |
| Admin GET /admin/users | Allow | Pass |
| Missing DPoP | Deny | Pass |
| Wrong key | Deny | Pass |
| Replay | Deny second request | Pass |
| Bypass backend | Blocked | Pass |
| mTLS with cert | Allow | Pass |

## 8. Hạn Chế

- Demo chạy trên một VPS, không phải production multi-node network.
- Backend còn đơn giản.
- Vault PKI chủ yếu để minh họa cấp cert/TTL/role.
- Một số giá trị secret dùng dev mode, không dùng production.

## 9. Kết Luận

- Token không còn là bearer token thuần.
- Request phải chứng minh sở hữu private key.
- Replay bị phát hiện bằng `jti`.
- Policy tách khỏi backend bằng OPA.
- Backend không nhận request trực tiếp ngoài Gateway.

## 10. Câu Hỏi Dự Kiến

**Public key client phân phối thế nào?**

Qua `cnf.jkt` trong access token.

**Ai verify token?**

`authz`, không phải backend.

**Backend có verify token không?**

Không. Backend chỉ nhận request đã qua Gateway và headers identity.

**Nếu authz down thì sao?**

Gateway fail-closed, deny request.

**Vì sao cần Redis?**

Để lưu DPoP `jti`, chống replay.

**Vì sao cần OPA?**

Để quản lý policy tập trung, deny-by-default.

**Website demo host ở đâu?**

Host cùng VPS bằng Docker Compose. Caddy đứng trước `demo-web`, tự lấy Let's Encrypt certificate cho domain thật, giúp browser hiện connection secure.
