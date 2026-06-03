# Demo Runbook

Runbook này dùng để chạy demo trên VPS.

## 1. Chuẩn Bị

SSH vào VPS:

```bash
ssh -i <path-to-key.pem> ubuntu@<VPS_PUBLIC_IP>
```

Vào repo:

```bash
cd ~/NT219-ZeroTrustAPIAuth
```

Pull code mới:

```bash
git pull
```

Sinh cert demo:

```bash
bash pki/setup-pki.sh
```

Start stack:

```bash
docker compose up -d --build
docker compose ps
```

Expected services:

```text
vault
keycloak
redis
opa
authz
user-service
resource-service
admin-service
envoy
```

## 2. Kiểm Tra Keycloak

Từ máy local mở SSH tunnel:

```powershell
ssh -i C:\Users\DARUNI\.ssh\zero-trust-api-key.pem -L 8080:127.0.0.1:8080 ubuntu@<VPS_PUBLIC_IP>
```

Browser:

```text
http://localhost:8080
```

Check realm:

- Realm: `zero-trust`
- Client: `demo-client`
- Users: `alice`, `admin`
- Roles: `user`, `admin`
- Token có `sub`, `aud`, `cnf.jkt`, `typ: DPoP`

## 3. Positive Tests Qua authz Trực Tiếp

```bash
source .venv-demo/bin/activate
python demo-client/client.py
```

Alice expected:

```text
GET /users -> 200 allow
GET /resources -> 200 allow
GET /admin/users -> 403
```

Admin expected:

```text
GET /users -> 200 allow
GET /resources -> 200 allow
GET /admin/users -> 200 allow
```

## 4. Negative Tests Qua authz

```bash
python demo-client/negative_tests.py
```

Expected:

```text
Missing DPoP -> 401
Wrong DPoP key -> 401
Replay same jti -> second request 401
Alice /admin/users -> 403
```

## 5. Positive Tests Qua Gateway

```bash
python demo-client/gateway_client.py
```

Alice expected:

```text
GET /users -> 200
GET /resources -> 200
GET /admin/users -> 403
```

Admin expected:

```text
GET /users -> 200
GET /resources -> 200
GET /admin/users -> 200
```

## 6. Negative Tests Qua Gateway

```bash
python demo-client/gateway_negative_tests.py
```

Expected:

```text
Baseline valid request -> 200
Missing DPoP -> 401
Wrong DPoP key -> 401
Replay same jti -> second request 401
Alice /admin/users -> 403
```

## 7. Bypass Gateway Test

```bash
python demo-client/bypass_gateway_test.py
```

Expected:

```text
http://127.0.0.1:8001/users -> blocked
http://127.0.0.1:8002/resources -> blocked
http://127.0.0.1:8003/admin/users -> blocked
```

Ý nghĩa: backend không expose port trực tiếp ra host.

## 8. mTLS Test

Không có client cert:

```bash
printf 'GET /users HTTP/1.1\r\nHost: user-service\r\n\r\n' | docker compose exec -T envoy openssl s_client \
  -connect user-service:8000 \
  -servername user-service \
  -CAfile /etc/envoy/certs/ca.crt \
  -quiet
```

Có Envoy client cert:

```bash
printf 'GET /users HTTP/1.1\r\nHost: user-service\r\n\r\n' | docker compose exec -T envoy openssl s_client \
  -connect user-service:8000 \
  -servername user-service \
  -CAfile /etc/envoy/certs/ca.crt \
  -cert /etc/envoy/certs/envoy-client.crt \
  -key /etc/envoy/certs/envoy-client.key \
  -quiet
```

Expected có cert:

```text
HTTP/1.1 200 OK
```

## 9. Vault PKI Demo

```bash
curl -s http://127.0.0.1:8200/v1/sys/health
```

Setup PKI:

```bash
export VAULT_TOKEN=root
bash vault/setup.sh
```

List secrets:

```bash
docker compose exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  vault vault secrets list
```

Issue thử cert:

```bash
docker compose exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=root \
  vault vault write pki/issue/backend-service \
  common_name=user-service \
  ttl=24h
```

## 10. Troubleshooting

Envoy config lỗi:

```bash
docker compose run --rm envoy envoy --mode validate -c /etc/envoy/envoy.yaml
docker compose logs --tail=100 envoy
```

Keycloak không vào được từ local:

```text
Kiểm tra SSH tunnel -L 8080:127.0.0.1:8080 còn mở không.
```

Token verify lỗi:

```bash
docker compose logs --tail=100 authz
```

Backend/Gateway lỗi:

```bash
docker compose logs --tail=100 envoy
docker compose logs --tail=100 user-service resource-service admin-service
```

Restart sạch:

```bash
docker compose down
bash pki/setup-pki.sh
docker compose up -d --build
```

## 11. Demo Website HTTPS

Website demo tối giản được host trong cùng Docker Compose bằng `demo-web` và `caddy`.

Start:

```bash
docker compose up -d --build demo-web caddy
docker compose ps demo-web caddy
```

Test nội bộ trên VPS:

```bash
curl -i http://127.0.0.1:8088
```

Mở qua SSH tunnel từ máy local nếu chưa có domain:

```powershell
ssh -i C:\Users\DARUNI\.ssh\zero-trust-api-key.pem -L 8088:127.0.0.1:8088 ubuntu@<VPS_PUBLIC_IP>
```

Browser:

```text
http://localhost:8088
```

Muốn browser hiện "Connection is secure", cần domain thật:

1. Tạo DNS A record trỏ domain/subdomain về public IP của VPS.
2. Mở Security Group AWS cho port `80` và `443`.
3. Set biến môi trường trước khi start Caddy:

```bash
export DEMO_SITE_ADDRESS=zero-trust-demo.example.com
docker compose up -d --build caddy demo-web
```

4. Mở:

```text
https://zero-trust-demo.example.com
```

Caddy sẽ tự lấy Let's Encrypt certificate nếu domain trỏ đúng VPS và port `80/443` reachable.

Website có các nút:

- Login Alice/Admin.
- GET `/users`.
- GET `/resources`.
- GET `/admin/users`.
- Missing DPoP.
- Wrong DPoP key.
- Replay same proof.
- Alice admin deny.

Lưu ý: website là demo UI. Phần DPoP private key/token được xử lý trong service `demo-web` server-side để demo ổn định; đường browser -> website được bảo vệ bằng HTTPS khi dùng domain + Caddy.
