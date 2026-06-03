# Zero-Trust API Authentication

Đồ án mô phỏng cơ chế xác thực API theo tư duy Zero-Trust: không request nào được tin mặc định, kể cả request đi vào từ token hợp lệ. Hệ thống kiểm tra token, bằng chứng sở hữu khóa DPoP, replay cache, policy OPA và đường đi qua Gateway trước khi cho backend xử lý.

## Mục Tiêu

- Chặn token theft: access token bị đánh cắp nhưng attacker không có private key DPoP thì không dùng được.
- Chặn replay: DPoP proof có `jti`, mỗi proof chỉ dùng một lần qua Redis replay cache.
- Chặn truy cập sai quyền: OPA deny-by-default theo role/method/path.
- Chặn bypass Gateway: backend không publish port trực tiếp; request phải đi qua Envoy Gateway.
- Mô phỏng mTLS nội bộ: Envoy dùng client certificate khi gọi backend.

## Thành Phần

- `identity/`: Keycloak realm/client/user/role.
- `authz/`: FastAPI ext_authz service, verify JWT, DPoP, replay, OPA.
- `policy/`: OPA/Rego policy.
- `gateway/`: Envoy Gateway.
- `backend/`: User, Resource, Admin services.
- `demo-client/`: scripts demo positive/negative cases.
- `pki/`, `vault/`: demo PKI, Vault PKI setup.
- `docs/`: runbook, kiến trúc, phân tích security, outline báo cáo.

## Chạy Nhanh Trên VPS

```bash
cd ~/NT219-ZeroTrustAPIAuth
bash pki/setup-pki.sh
docker compose up -d --build
docker compose ps
```

Runbook chi tiết nằm ở [docs/demo-runbook.md](docs/demo-runbook.md).

## Tài Liệu Báo Cáo

- [docs/architecture.md](docs/architecture.md): kiến trúc hệ thống.
- [docs/security-analysis.md](docs/security-analysis.md): threat model và cơ chế crypto.
- [docs/demo-runbook.md](docs/demo-runbook.md): kịch bản chạy demo.
- [docs/report-outline.md](docs/report-outline.md): dàn ý báo cáo/thuyết trình.
