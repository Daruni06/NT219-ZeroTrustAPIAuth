# Zero-Trust API Authentication — Hướng dẫn Đồ án

> **Môn:** Mật mã học (Cryptography)
> **Đề tài:** Zero-Trust API Authentication
> **Nhóm:** 3 người
> **Hạ tầng:** 1 VPS duy nhất + máy local của từng thành viên

---

## Mục lục

1. [Tổng quan đề tài](#1-tổng-quan-đề-tài)
2. [Kiến trúc hệ thống & Topology mạng](#2-kiến-trúc-hệ-thống--topology-mạng)
3. [Cấu trúc thư mục project](#3-cấu-trúc-thư-mục-project)
4. [Phân công & Task cụ thể](#4-phân-công--task-cụ-thể)
5. [Workflow & Timeline](#5-workflow--timeline)
6. [Môi trường phát triển](#6-môi-trường-phát-triển)
7. [Ghi chú từ thầy](#7-ghi-chú-từ-thầy)

---

## 1. Tổng quan đề tài

### Câu hỏi trung tâm

> *"Nếu kẻ tấn công đánh cắp được token hợp lệ của người dùng, cơ chế nào phát hiện ra hắn không phải chủ thật?"*

Đây là điểm phân biệt đề tài này với các đề tài API security khác:

| Đề tài | Trọng tâm |
|--------|-----------|
| Secure API Gateway | Bảo vệ tại lớp cổng vào: TLS, rate limit, WAF |
| Cloud API Security | Bảo vệ toàn bộ hạ tầng mạng công ty |
| **Zero-Trust API Auth** | **Cơ chế xác thực danh tính & ràng buộc token với client cụ thể** |

### 3 Rủi ro cần giải quyết

| # | Rủi ro | Giải pháp Crypto |
|---|--------|-----------------|
| 1 | Bearer token bị đánh cắp — ai cầm cũng dùng được | **DPoP** (Demonstrating Proof-of-Possession) + Ed25519 |
| 2 | Replay attack — gửi lại request cũ đã bắt được | **TLS 1.3** (tắt 0-RTT) + **DPoP nonce/jti** + Redis cache |
| 3 | Bypass gateway — gọi thẳng backend trong mạng nội bộ | **mTLS** (mutual TLS) nội bộ + firewall rule |

### Các bên liên quan

- **Bên 1 — Người dùng cuối:** Không kiểm soát được thiết bị. Dùng Web Browser hoặc Mobile App.
- **Bên 2 — Nhà cung cấp dịch vụ:** Kiểm soát toàn bộ hạ tầng. Gồm 7 network node.
- **Bên 3 — Đối tác / 3rd-party:** Không kiểm soát code hay môi trường. Gọi API dạng service-to-service.

---

## 2. Kiến trúc hệ thống & Topology mạng

### 2.1 Tổng quan 3 bên & 8 node

```
┌─────────────────────┐   ┌──────────────────────────────────┐   ┌─────────────────────┐
│  BÊN 1              │   │  BÊN 2                           │   │  BÊN 3              │
│  Người dùng cuối    │   │  Nhà cung cấp dịch vụ            │   │  Đối tác / 3rd-party│
│                     │   │                                  │   │                     │
│  Node 1             │   │  Node 2: API Gateway             │   │  Node 8             │
│  Thiết bị User      │   │  Node 3: Keycloak IdP            │   │  Partner Server     │
│  Browser/Mobile App │   │  Node 4: ext_authz               │   │  Backend đối tác    │
│                     │   │  Node 5: OPA                     │   │                     │
│                     │   │  Node 6: Backend Services        │   │                     │
│                     │   │  Node 7: Vault / PKI             │   │                     │
└─────────────────────┘   └──────────────────────────────────┘   └─────────────────────┘
```

### 2.2 Topology mạng (1 VPS duy nhất)

```
════════════════════════════════════════════════════════════════════════════════
  TOPOLOGY MẠNG — ZERO-TRUST API AUTHENTICATION SYSTEM
  Hạ tầng: 1 VPS, mỗi service bind port riêng, firewall phân tách
════════════════════════════════════════════════════════════════════════════════

INTERNET (Untrusted)
│
│  [HOST: Thiết bị User]            [HOST: Partner Server — Bên 3]
│   App: Browser / Mobile App        App: Backend service đối tác
│   - Tự sinh Ed25519 key pair
│   - Giữ DPoP private key (không gửi đi đâu)
│        │ HTTPS :443                         │ mTLS :443
│        │ + DPoP proof header                │ + client certificate
│        └──────────────┬────────────────────-┘
│                       │
│   ════════════════════▼═══════════════════════════════════
│   VÙNG PUBLIC — Expose ra internet
│   ════════════════════════════════════════════════════════
│   │
│   │  [HOST: VPS — <IP_PUBLIC>]
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Node 2 — API Gateway                           │
│   │   │  App: Envoy Proxy                               │
│   │   │  Port public : :443 (HTTPS từ User)             │
│   │   │                :443 (mTLS từ Partner)           │
│   │   │  Port internal: :8080 → ext_authz               │
│   │   │                 :8081 → Keycloak                │
│   │   │                 :8082 → Backend services        │
│   │   │                                                 │
│   │   │  Vai trò: Điểm vào DUY NHẤT. Terminate TLS.     │
│   │   │  Forward sang ext_authz trước, nếu allow        │
│   │   │  mới forward sang Backend.                      │
│   │   └─────────────────────────────────────────────────┘
│   │
│   ════════════════════════════════════════════════════════
│   VÙNG INTERNAL — Chỉ nhận kết nối từ Gateway
│   ════════════════════════════════════════════════════════
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Node 3 — Keycloak IdP                          │
│   │   │  App: Keycloak Identity Server                  │
│   │   │  Port: :8080 (internal), :8443 (HTTPS login)    │
│   │   │                                                 │
│   │   │  Vai trò: CẤP TOKEN (trọng tâm đề tài).         │
│   │   │  - Xác thực user qua OIDC + PKCE                │
│   │   │  - Cấp JWT có claim "cnf" = public key client   │
│   │   │  - Công bố JWKS endpoint cho ext_authz          │
│   │   └─────────────────────────────────────────────────┘
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Node 4 — ext_authz                             │
│   │   │  App: Custom Python service (FastAPI)           │
│   │   │  Port: :8090 (internal, nhận từ Gateway)        │
│   │   │                                                 │
│   │   │  Vai trò: XÁC MINH TOKEN — 3 bước tuần tự:      │
│   │   │  Bước 1: Lấy JWKS từ Keycloak → verify JWT      │
│   │   │  Bước 2: Đọc "cnf" trong JWT → verify DPoP      │
│   │   │  Bước 3: Check jti + timestamp → chống replay   │
│   │   │  → Gọi OPA hỏi quyền → trả allow/deny           │
│   │   └─────────────────────────────────────────────────┘
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Node 5 — OPA (Open Policy Agent)               │
│   │   │  App: OPA binary                                │
│   │   │  Port: :8181 (internal, nhận từ ext_authz)      │
│   │   │                                                 │
│   │   │  Vai trò: RA QUYẾT ĐỊNH PHÂN QUYỀN.             │
│   │   │  - Nhận: user-id, role, scope, method, path     │
│   │   │  - Áp dụng deny-by-default (Rego policy)        │
│   │   │  - Trả: allow/deny + lý do → ghi audit log      │
│   │   └─────────────────────────────────────────────────┘
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Node 6 — Backend Services                      │
│   │   │  App 1: User Service     (FastAPI) :8001        │
│   │   │  App 2: Admin Service    (FastAPI) :8002        │
│   │   │  App 3: Resource Service (FastAPI) :8003        │
│   │   │                                                 │
│   │   │  Vai trò: XỬ LÝ NGHIỆP VỤ.                      │
│   │   │  - Chỉ nhận mTLS từ Gateway                     │
│   │   │  - Nhận header x-user-id, x-scopes từ Gateway   │
│   │   │  - Không tự verify token                        │
│   │   │  - Giao tiếp DB qua API nội bộ, không trực tiếp │
│   │   └─────────────────────────────────────────────────┘
│   │
│   ════════════════════════════════════════════════════════
│   VÙNG DATA — Chỉ nhận kết nối từ Backend
│   ════════════════════════════════════════════════════════
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Database & Cache                               │
│   │   │  App 1: MySQL        :3306 (chỉ từ Backend)     │
│   │   │  App 2: Redis        :6379 (chỉ từ ext_authz)   │
│   │   │                                                 │
│   │   │  MySQL  — lưu dữ liệu người dùng, giao dịch     │
│   │   │  Redis  — replay cache (jti + timestamp)        │
│   │   └─────────────────────────────────────────────────┘
│   │
│   ════════════════════════════════════════════════════════
│   VÙNG MANAGEMENT — Chỉ nhận kết nối từ service nội bộ
│   ════════════════════════════════════════════════════════
│   │
│   │   ┌─────────────────────────────────────────────────┐
│   │   │  Node 7 — HashiCorp Vault                       │
│   │   │  App: HashiCorp Vault binary                    │
│   │   │  Port: :8200 (HTTPS, chỉ từ service nội bộ)     │
│   │   │                                                 │
│   │   │  Vai trò: QUẢN LÝ KHÓA TẬP TRUNG.               │
│   │   │  - Cấp JWT signing key (Ed25519) cho Keycloak   │
│   │   │  - Cấp chứng chỉ X.509 (TTL 24-48h) cho mTLS    │
│   │   │  - Tự động rotate key                           │
│   │   │  - Blast radius lớn nhất nếu bị compromise      │
│   │   └─────────────────────────────────────────────────┘
```

### 2.3 Sơ đồ luồng request

```
Bước 1  Đăng nhập     Node 1 → Node 3   OIDC + PKCE
                       Node 3 cấp JWT có "cnf" = public key của User

Bước 2  Gọi API       Node 1 → Node 2   HTTPS :443 + JWT + DPoP proof header

Bước 3  Verify        Node 2 → Node 4   Gateway chuyển sang ext_authz :8090
                       Node 4 → Node 3   Lấy JWKS, verify chữ ký JWT (Ed25519)
                       Node 4            Đọc "cnf" → verify DPoP proof
                       Node 4 → Redis    Check replay cache (jti + timestamp)
                       Node 4 → Node 5  Hỏi OPA: user này được làm gì?
                       Node 5            Deny-by-default → trả allow/deny

Bước 4  Kết quả       Node 2 → Node 6   Nếu allow: forward qua mTLS :8001-8003
                       Node 2            Nếu deny: trả 401/403, ghi log lý do
                       Node 6 → MySQL    Query/write dữ liệu
```

### 2.4 Firewall rules

```
Nguồn              → Đích               Port          Action
──────────────────────────────────────────────────────────────
Internet           → Gateway            :443          ALLOW
Gateway            → ext_authz          :8090         ALLOW
Gateway            → Keycloak           :8080         ALLOW
Gateway            → Backend            :8001-8003    ALLOW
ext_authz          → Keycloak           :8080         ALLOW (lấy JWKS)
ext_authz          → OPA                :8181         ALLOW
ext_authz          → Redis              :6379         ALLOW
Backend            → MySQL              :3306         ALLOW
Backend            → Vault              :8200         ALLOW
Keycloak           → Vault              :8200         ALLOW
ext_authz          → Vault              :8200         ALLOW
Internet           → Backend            *             DENY
Internet           → MySQL/Redis        *             DENY
Internet           → Vault              *             DENY
```

### 2.5 Cơ chế phân phối Public Key

**Loại 1 — Public key của CLIENT (DPoP key):**
```
Client tự sinh cặp Ed25519 key pair
→ Gửi public key lên Keycloak khi xin token
→ Keycloak nhúng vào JWT claim "cnf": { "jwk": <public_key> }
→ ext_authz đọc "cnf" từ token → biết public key thuộc về chủ token đó
→ Không cần phân phối riêng — public key đi cùng token
```

**Loại 2 — Public key của SERVER (JWT signing key):**
```
Keycloak giữ private key (lấy từ Vault)
→ Công bố public key qua JWKS endpoint:
   GET https://<VPS_IP>:8443/realms/zero-trust/protocol/openid-connect/certs
→ ext_authz gọi endpoint này → lấy public key → verify chữ ký JWT
→ ext_authz cache lại, định kỳ refresh khi key rotation
```

---

## 3. Cấu trúc thư mục project

```
zero-trust-api-auth/
│
├── docs/                              # Tài liệu
│   ├── architecture.md               # Kiến trúc hệ thống (file này)
│   ├── topology.png                  # Diagram xuất từ mermaid.live
│   └── proposal.md                   # Proposal gốc
│
├── infra/                             # Cấu hình hạ tầng VPS
│   ├── firewall/
│   │   └── rules.sh                  # ⚙️ Script tạo firewall rule (ufw/iptables)
│   └── hosts.env                     # IP thật của VPS sau khi thuê
│
├── gateway/                           # Envoy Proxy
│   ├── envoy.yaml                    # ⚙️ CONFIG — routing, TLS, mTLS, ext_authz
│   └── certs/                        # TLS cert (do Vault cấp, không commit lên git)
│       ├── server.crt
│       └── server.key
│
├── identity/                          # Keycloak IdP
│   ├── keycloak.conf                 # ⚙️ CONFIG — port, DB, TLS
│   └── realm-export.json             # ⚙️ CONFIG — export realm, client, DPoP setting
│
├── authz/                             # ext_authz service — PHẦN CODE CHÍNH
│   ├── main.py                       # 💻 CODE — FastAPI app, endpoint /verify
│   ├── jwt_verify.py                 # 💻 CODE — fetch JWKS, verify JWT (Ed25519)
│   ├── dpop.py                       # 💻 CODE — verify DPoP proof header
│   ├── replay_cache.py               # 💻 CODE — check jti/nonce qua Redis
│   ├── opa_client.py                 # 💻 CODE — gọi OPA hỏi policy
│   ├── config.yaml                   # ⚙️ CONFIG — URL Keycloak, OPA, Redis
│   └── requirements.txt
│
├── policy/                            # OPA — Phân quyền
│   ├── policy.rego                   # 💻 CODE — rule phân quyền (ngôn ngữ Rego)
│   └── opa.yaml                      # ⚙️ CONFIG — port, bundle path
│
├── backend/                           # Backend Services
│   ├── user_service/
│   │   ├── main.py                   # 💻 CODE — GET /users, GET /users/{id}
│   │   ├── db.py                     # 💻 CODE — kết nối MySQL
│   │   └── requirements.txt
│   ├── admin_service/
│   │   ├── main.py                   # 💻 CODE — GET /admin/users, DELETE /admin/users/{id}
│   │   ├── db.py                     # 💻 CODE — kết nối MySQL
│   │   └── requirements.txt
│   └── resource_service/
│       ├── main.py                   # 💻 CODE — GET /resources, POST /resources
│       ├── db.py                     # 💻 CODE — kết nối MySQL
│       └── requirements.txt
│
├── database/                          # MySQL + Redis
│   ├── init.sql                      # 💻 CODE — tạo schema, bảng, dữ liệu mẫu
│   ├── mysql.cnf                     # ⚙️ CONFIG — bind-address, max_connections
│   └── redis.conf                    # ⚙️ CONFIG — bind IP, requirepass, maxmemory
│
├── vault/                             # HashiCorp Vault
│   ├── vault.hcl                     # ⚙️ CONFIG — storage, listener, TLS
│   └── setup.sh                      # 💻 CODE — script init PKI, tạo role, cấp cert
│
├── pki/                               # Quản lý certificate
│   └── setup-pki.sh                  # 💻 CODE — tạo Root CA, cấp cert cho các service
│
└── demo-client/                       # Chạy local khi demo
    ├── client.py                     # 💻 CODE — sinh Ed25519 key, login OIDC,
    │                                 #           tạo DPoP proof, gọi API
    └── requirements.txt
```

> **Chú ý:** Thư mục `certs/` và file `hosts.env` không được commit lên Git.
> Tạo file `.gitignore` để loại trừ.

---

## 4. Phân công & Task cụ thể

### Người 1 — Hạ tầng & Gateway

**Phụ trách:** `infra/`, `gateway/`, `vault/`, `pki/`

| Task | File | Dùng gì | Ghi chú |
|------|------|---------|---------|
| Thuê VPS | — | DigitalOcean / Vultr / Linode | ~$6-12/tháng |
| Tạo firewall rule | `infra/firewall/rules.sh` | bash + ufw | Block theo port, chỉ allow đúng nguồn |
| Cấu hình Envoy Gateway | `gateway/envoy.yaml` | YAML config | Routing, TLS terminate, ext_authz endpoint, mTLS |
| Cài & init Vault | `vault/vault.hcl` + `vault/setup.sh` | HashiCorp Vault | Init PKI engine, tạo Root CA |
| Cấp cert cho services | `pki/setup-pki.sh` | Vault PKI API | X.509 TTL 24-48h cho mTLS nội bộ |
| Ghi lại IP/port | `infra/hosts.env` | text | Chia sẻ cho cả nhóm |

**Kết quả bàn giao:** VPS chạy được, Gateway online, cert đã cấp cho tất cả service.

---

### Người 2 — Authentication Core (phần quan trọng nhất)

**Phụ trách:** `identity/`, `authz/`, `policy/`

| Task | File | Dùng gì | Ghi chú |
|------|------|---------|---------|
| Cài Keycloak | `identity/keycloak.conf` | Keycloak 23+ | Bật DPoP trong realm setting |
| Tạo realm & client | `identity/realm-export.json` | Keycloak Admin UI → Export | Client phải bật DPoP support |
| Viết FastAPI app | `authz/main.py` | Python + FastAPI | Endpoint POST /verify nhận từ Gateway |
| Verify JWT | `authz/jwt_verify.py` | python-jose / PyJWT | Fetch JWKS từ Keycloak, verify Ed25519 |
| Verify DPoP proof | `authz/dpop.py` | cryptography library | Đọc claim "cnf", verify chữ ký DPoP header |
| Chống replay | `authz/replay_cache.py` | redis-py | Lưu jti + timestamp, TTL = token expiry |
| Gọi OPA | `authz/opa_client.py` | httpx | POST input → nhận allow/deny |
| Viết policy | `policy/policy.rego` | Rego language | deny-by-default, rule theo role/path/method |

**Kết quả bàn giao:** ext_authz verify được token, DPoP, replay; OPA phân quyền đúng role.

---

### Người 3 — Backend & Demo Client

**Phụ trách:** `backend/`, `database/`, `demo-client/`

| Task | File | Dùng gì | Ghi chú |
|------|------|---------|---------|
| Viết User Service | `backend/user_service/main.py` | Python + FastAPI | GET /users, GET /users/{id} |
| Viết Admin Service | `backend/admin_service/main.py` | Python + FastAPI | GET /admin/users, DELETE /admin/users/{id} |
| Viết Resource Service | `backend/resource_service/main.py` | Python + FastAPI | GET /resources, POST /resources |
| Kết nối MySQL | `backend/*/db.py` | mysql-connector-python | Mỗi service kết nối riêng |
| Tạo schema DB | `database/init.sql` | SQL | Bảng users, resources, audit_log |
| Config MySQL | `database/mysql.cnf` | text config | Chỉ cho phép IP nội bộ |
| Config Redis | `database/redis.conf` | text config | requirepass, bind nội bộ |
| Viết demo client | `demo-client/client.py` | Python + cryptography | **File quan trọng nhất khi demo** |

**Kết quả bàn giao:** 3 backend service chạy, DB có data mẫu, demo client gọi API thành công.

---

## 5. Workflow & Timeline

### Giai đoạn 1 — Setup (Tuần 1)

```
Người 1: Thuê VPS → SSH test → Cài Envoy, Vault
         → Chạy setup-pki.sh → Cấp cert → Chia sẻ hosts.env cho nhóm

Người 2: Cài Keycloak local → Tạo realm, bật DPoP → Test login OIDC
         → Bắt đầu viết authz/jwt_verify.py

Người 3: Thiết kế schema DB → Viết init.sql
         → Viết backend user_service local → Test GET /users
```

### Giai đoạn 2 — Development (Tuần 2-3)

```
Người 1: Viết envoy.yaml → Test routing → Integrate ext_authz vào Gateway
         → Viết firewall/rules.sh → Apply lên VPS

Người 2: Viết đủ 4 file authz/ → Test từng bước (JWT → DPoP → replay → OPA)
         → Viết policy.rego → Test phân quyền

Người 3: Viết đủ 3 backend service → Viết demo-client/client.py
         → Test client.py gọi thẳng backend (chưa qua Gateway)
```

### Giai đoạn 3 — Integration (Tuần 4)

```
Cả nhóm:
  1. Deploy tất cả lên VPS
  2. Test luồng đầy đủ: client.py → Gateway → ext_authz → OPA → Backend → MySQL
  3. Test các kịch bản tấn công:
     - Gửi token không có DPoP header → phải bị từ chối
     - Gửi lại request cũ (replay) → phải bị từ chối
     - Gọi /admin với role user → phải bị từ chối
     - Gọi thẳng backend không qua Gateway → phải bị từ chối (mTLS fail)
  4. Sửa bug, tinh chỉnh
```

### Giai đoạn 4 — Demo prep (Tuần 5)

```
Người 3: Chuẩn bị script demo client.py — show rõ từng bước
Người 2: Chuẩn bị giải thích luồng verify trong ext_authz
Người 1: Chuẩn bị show firewall log, Vault cert management
Cả nhóm: Chạy thử demo nhiều lần, chuẩn bị trả lời câu hỏi của thầy
```

---

## 6. Môi trường phát triển

### Máy local (từng thành viên)

```
- Python 3.11+
- Docker Desktop (test local trước khi deploy VPS)
- Postman hoặc curl (test API)
- Git + GitHub (version control, chia sẻ code)
```

### Thư viện Python cần thiết

```
# authz/requirements.txt
fastapi
uvicorn
python-jose[cryptography]    # verify JWT
cryptography                 # Ed25519, DPoP
httpx                        # gọi OPA, Keycloak
redis                        # replay cache
pyyaml                       # đọc config.yaml

# backend/requirements.txt
fastapi
uvicorn
mysql-connector-python

# demo-client/requirements.txt
cryptography                 # sinh Ed25519 key pair
httpx                        # gọi API
requests-oauthlib            # OIDC flow
```

### VPS khuyến nghị

```
Provider : DigitalOcean / Vultr / Linode
Spec     : 2 vCPU, 4GB RAM, 80GB SSD (~$24/tháng)
OS       : Ubuntu 22.04 LTS
```

### Quy trình deploy lên VPS

```bash
# 1. Clone repo trên VPS
git clone https://github.com/<nhom>/zero-trust-api-auth.git

# 2. Chạy setup Vault + PKI
bash vault/setup.sh
bash pki/setup-pki.sh

# 3. Apply firewall rules
bash infra/firewall/rules.sh

# 4. Start các service theo thứ tự:
#    Vault → MySQL → Redis → Keycloak → OPA → ext_authz → Backend → Gateway
```

---

## 7. Ghi chú từ thầy

> *Đồ án không hướng đến implement phương pháp crypto, mà là ứng dụng cryptography để giải quyết vấn đề thực tế.*
> *Chú ý soạn báo cáo đúng logic, nêu rõ security risks và project goals, kiến trúc giải pháp, phương án triển khai, và kết quả triển khai demo.*

**Những gì thầy sẽ hỏi:**

1. **Bài toán:** Trong trường hợp nào thì gặp rủi ro gì? *(tập trung vào đây)*
2. **Hệ thống:** Có những node mạng nào? Vai trò từng node? Giao tiếp qua giao thức gì?
3. **Cơ chế cấp token:** Ai cấp, cấp cái gì, cấp như thế nào?
4. **Cơ chế verify:** Ai verify, verify cái gì, verify như thế nào?
5. **Phân phối public key:** Public key của ai, phân phối bằng cách nào, làm sao biết nó là của ai?
6. **Tại sao dùng crypto này** mà không phải crypto khác?

**Những điều phải tránh:**

- Không nói chung chung "hệ thống bảo mật hơn" — phải chỉ rõ bảo mật cái gì, ở đâu, bằng cơ chế nào.
- Không để ext_authz fail-open (nếu service down thì phải deny tất cả, không phải allow).
- Không để backend có port public — chỉ nhận kết nối mTLS từ Gateway.
- Không lưu private key cục bộ trong service — phải lấy từ Vault.
- Database không giao tiếp trực tiếp — chỉ qua API của Backend.

---

*File này được tổng hợp từ quá trình tư vấn đề tài. Cập nhật lần cuối theo topology 1 VPS + MySQL.*

---

## 8. Công việc tiếp theo sau khi dựng VPS & stack nền

> Mục này ghi lại các bước cần làm sau khi VPS đã SSH được, Docker chạy được, và stack nền Keycloak + OPA + Redis + ext_authz đã khởi động thành công.

### 8.1 Chia sẻ code qua GitHub

**Phụ trách:** Toàn bộ nhóm

1. Tạo GitHub repository cho project.
2. Push toàn bộ source code hiện tại lên repository.
3. Mời các thành viên còn lại vào repository với quyền phù hợp.
4. Mỗi thành viên clone repository về máy local.
5. Thống nhất quy trình làm việc: pull trước khi sửa, commit theo phần phụ trách, push branch riêng nếu cần review.
6. Cách cập nhật code trên VPS sau khi đã có repo Github:
```bash
cd ~/zero-trust-api
git remote add origin https://github.com/<your-username>/zero-trust-api.git
git pull origin main
docker compose up -d --build
```

### 8.2 Chia sẻ quyền test trên VPS AWS

**Phụ trách:** Người 1 + Toàn bộ nhóm

1. Người 1 quản lý VPS, Security Group, firewall, Docker, port public/internal.
2. Các thành viên gửi public SSH key của mình cho Người 1. `ssh-keygen -t ed25519 -C "member-name-zero-trust"`
3. Người 1 thêm public key vào file `~/.ssh/authorized_keys` trên VPS.
4. Security Group chỉ mở SSH port `22` theo IP public của từng thành viên, không mở lâu dài `0.0.0.0/0`.
5. Mỗi thành viên SSH vào VPS bằng `ssh ubuntu@<VPS_PUBLIC_IP>`, test Keycloak hoạt động hay không bằng SSH tunnel `ssh -L 8080:127.0.0.1:8080 ubuntu@<VPS_PUBLIC_IP>` rồi mở http://localhost:8080.
6. Không chia sẻ private key AWS gốc qua chat.
7. Không commit file secret như `.env`, `infra/hosts.env`, cert, private key.

### 8.3 Kiểm tra Keycloak realm

**Phụ trách:** Người 2

1. Xác nhận realm `zero-trust` đã import thành công.
2. Xác nhận client `demo-client` tồn tại.
3. Xác nhận users mẫu `alice` và `admin` tồn tại.
4. Xác nhận roles `user` và `admin` đã gán đúng.
5. Kiểm tra client setting liên quan PKCE và DPoP.

### 8.4 Test OPA policy

**Phụ trách:** Người 2

1. Chạy các input mẫu trong `policy/testdata/`.
2. Kiểm tra case user gọi `/users` được allow.
3. Kiểm tra case user gọi `/admin/users` bị deny.
4. Kiểm tra case admin gọi `/admin/users` được allow.
5. Kiểm tra case user `POST /resources` thiếu scope `resource:write` bị deny.
6. Kiểm tra case user `POST /resources` có scope `resource:write` được allow.

### 8.5 Lấy token thật từ Keycloak

**Phụ trách:** Người 2

1. Lấy access token cho user `alice` và `admin`.
2. Decode JWT để kiểm tra các claim quan trọng: `iss`, `aud`, `sub`, `preferred_username`, `realm_access.roles`, `scope`.
3. Kiểm tra token có claim `cnf` phục vụ DPoP hay chưa.
4. Nếu chưa có `cnf`, chỉnh lại cấu hình Keycloak/client hoặc bổ sung cơ chế demo để nhúng public key client vào token.

### 8.6 Hoàn thiện demo client

**Phụ trách:** Người 3 + Người 2

1. Sinh Ed25519 key pair phía client.
2. Tạo DPoP proof JWT cho từng request.
3. Login Keycloak lấy access token.
4. Gửi request kèm `Authorization: Bearer <token>` và `DPoP: <proof>`.
5. Chuẩn bị demo case token bị đánh cắp nhưng attacker không có private key nên không gọi API được.

### 8.7 Test trực tiếp ext_authz

**Phụ trách:** Người 2

1. Gửi request tới endpoint `/verify`.
2. Kiểm tra flow verify tuần tự: JWT -> DPoP -> replay cache -> OPA.
3. Kiểm tra response allow/deny và headers identity trả về cho Gateway.
4. Đảm bảo service fail-closed khi OPA/Redis/Keycloak lỗi.

### 8.8 Negative tests bắt buộc

**Phụ trách:** Người 2 + Toàn bộ nhóm

1. Thiếu DPoP header -> deny.
2. DPoP ký bằng key khác token `cnf` -> deny.
3. Replay cùng `jti` -> deny.
4. User thường gọi `/admin` -> deny.
5. Admin gọi `/admin` -> allow.
6. Token hết hạn hoặc sai issuer/audience -> deny.

### 8.9 Viết Envoy Gateway config

**Phụ trách:** Người 1 + Người 2

1. Cấu hình Envoy nhận HTTPS public.
2. Cấu hình ext_authz filter gọi service `authz`.
3. Chỉ forward sang backend nếu authz allow.
4. Inject identity headers như `x-user-id`, `x-user-name`, `x-user-roles`, `x-scopes`.
5. Đảm bảo authz lỗi thì Gateway deny, không fail-open.

### 8.10 Viết backend demo tối thiểu

**Phụ trách:** Người 3

1. Viết User Service với endpoint `/users`.
2. Viết Resource Service với endpoint `/resources`.
3. Viết Admin Service với endpoint `/admin/users`.
4. Backend chỉ tin headers do Gateway inject.
5. Backend không tự verify token.
6. Backend không mở public port trực tiếp ra Internet.

### 8.11 Tích hợp end-to-end

**Phụ trách:** Toàn bộ nhóm

1. Chạy luồng đầy đủ: demo-client -> Gateway -> ext_authz -> OPA -> Backend.
2. Ghi log từng bước verify để phục vụ demo.
3. Test lại toàn bộ positive/negative cases.
4. Kiểm tra firewall và Security Group đúng nguyên tắc zero-trust.

### 8.12 Chuẩn bị báo cáo và demo script

**Phụ trách:** Toàn bộ nhóm

1. Viết rõ bài toán: token bị đánh cắp, replay, bypass gateway.
2. Nêu rõ cơ chế crypto dùng để chặn từng rủi ro.
3. Chuẩn bị script demo theo từng kịch bản.
4. Chuẩn bị câu trả lời cho các câu hỏi: ai cấp token, ai verify, public key phân phối thế nào, tại sao dùng DPoP/Ed25519/mTLS.
